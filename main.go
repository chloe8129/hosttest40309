package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultPort               = "8080"
	compatAltPort             = "3000"
	compactSelfMemMB          = 40
	compactWorkerMemMB        = 136
	standardSelfMemMB         = 96
	standardWorkerMemMB       = 380
	defaultGOMAXPROCS         = 2
	gatewayMemPercent         = 14
	workerMemPercent          = 54
	compactTierThresholdMB    = 384
	httpDrainTimeout          = 8 * time.Second
	edgeKeepAlivePeriod       = 15 * time.Second
	drainPropagationWindow    = 400 * time.Millisecond
	startupOrchestrationDelay = 3 * time.Second
	dnsPropagationSettleDelay = 4 * time.Second
	firstBytePeekTimeout      = 2 * time.Second
	tcpUserTimeoutOpt         = 18
)

var compactMemoryMode atomic.Bool

var knownBotHostingNodeIPs = map[string]string{
	// Germany (Hetzner Falkenstein) Nodes
	"167.235.13.16":  "de-fra1", // de1
	"157.90.181.183": "de-fra1", // de3
	"148.251.195.88": "de-fra1", // prem-eu1
	"176.9.16.103":   "de-fra1", // prem-eu2
	"88.99.241.221":  "de-fra1", // prem-eu3
	"138.201.62.129": "de-fra1", // prem-eu4
	"88.99.37.82":    "de-fra1", // prem-eu5

	// Finland (Hetzner Helsinki) New Panel Nodes
	"65.108.103.151": "fi-hel1", // fi3
	"65.21.202.154":  "fi-hel1", // fi4
	"95.216.12.48":   "fi-hel1", // fi9
	"37.27.169.207":  "fi-hel1", // fi10
	"95.217.140.174": "fi-hel1", // fi12
	"95.217.148.96":  "fi-hel1", // fi13
	"157.180.7.55":   "fi-hel1", // fi14
	"37.27.54.248":   "fi-hel1", // fi15
	"37.27.141.177":  "fi-hel1", // fi16

	// Finland (Hetzner Helsinki) Legacy Panel Nodes
	"65.109.58.133":  "fi-hel1", // fi1
	"65.21.111.33":   "fi-hel1", // fi2
	"135.181.204.26": "fi-hel1", // fi5
	"95.216.185.64":  "fi-hel1", // fi6
	"65.108.198.187": "fi-hel1", // fi7
	"95.217.75.43":   "fi-hel1", // fi8
	"37.27.22.104":   "fi-hel1", // fi11

	// USA Nodes
	"5.161.206.92":   "us-east4", // us1
	"194.140.197.43": "us-east4", // us2
	"38.58.183.178":  "us-east4", // us3
}

func isCompactMemoryTier() bool {
	return compactMemoryMode.Load()
}

func cgroupMemoryLimit() (uint64, bool) {
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}

	for _, envKey := range []string{"SERVER_MEMORY", "MEMORY_LIMIT", "BERMUDA_CONTAINER_MEM_MB"} {
		if raw := strings.TrimSpace(getEnv(envKey, "")); raw != "" {
			if mb, err := strconv.ParseUint(raw, 10, 64); err == nil && mb >= 64 && mb <= 65536 {
				return mb << 20, true
			}
		}
	}

	return 0, false
}

func deriveMemoryBudget() (gwMB, workerMB int, compact bool) {
	gwMB, workerMB, compact = compactSelfMemMB, compactWorkerMemMB, true

	limit, limited := cgroupMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		if totalMB > compactTierThresholdMB {
			compact = false
			gwMB = totalMB * gatewayMemPercent / 100
			workerMB = totalMB * workerMemPercent / 100

			allowedMB := totalMB * 68 / 100
			if gwMB < 48 {
				gwMB = 48
			}
			if workerMB < 128 {
				workerMB = 128
			}
			if total := gwMB + workerMB; total > allowedMB && allowedMB >= 176 {
				gwMB = allowedMB * gatewayMemPercent / 68
				workerMB = allowedMB * workerMemPercent / 68
			}
		} else {
			compact = true
			gwMB = totalMB * 15 / 100
			workerMB = totalMB * 52 / 100
			if gwMB < 32 {
				gwMB = 32
			}
			if gwMB > 44 {
				gwMB = 44
			}
			if workerMB < 96 {
				workerMB = 96
			}
			if workerMB > 140 {
				workerMB = 140
			}
		}
	}

	if explicitLow := strings.ToLower(strings.TrimSpace(getEnv("BERMUDA_LOW_MEM", ""))); explicitLow == "true" || explicitLow == "1" {
		compact = true
		if gwMB > compactSelfMemMB {
			gwMB = compactSelfMemMB
		}
		if workerMB > compactWorkerMemMB {
			workerMB = compactWorkerMemMB
		}
	} else if explicitLow == "false" || explicitLow == "0" {
		compact = false
		if !limited {
			gwMB, workerMB = standardSelfMemMB, standardWorkerMemMB
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	workerMB = getEnvInt("BERMUDA_WORKER_MEM_MB", getEnvInt("BERMUDA_XRAY_MEM_MB", workerMB))
	compactMemoryMode.Store(compact)
	return gwMB, workerMB, compact
}

func applyMemoryCeiling(selfMB int, compact bool) {
	if selfMB < 32 {
		selfMB = 32
	}
	debug.SetMemoryLimit(int64(selfMB) << 20)
	if compact {
		debug.SetGCPercent(50)
	} else {
		debug.SetGCPercent(100)
	}
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() int {
	n := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	if n == 0 {
		if q, ok := cgroupCPUQuota(); ok {
			n = int(math.Ceil(q))
		}
	}
	if n < 2 {
		n = defaultGOMAXPROCS
	}
	if cpus := runtime.NumCPU(); n > cpus && cpus > 0 {
		n = cpus
	}
	runtime.GOMAXPROCS(n)
	return n
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "${{") || strings.HasPrefix(h, "$") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if slashIdx := strings.IndexByte(h, '/'); slashIdx != -1 {
		h = h[:slashIdx]
	}
	h = strings.TrimRight(h, "/.")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func isBotHostingNodeHost(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	if _, ok := knownBotHostingNodeIPs[h]; ok {
		return true
	}
	if _, ok := knownBotHostingNodeFQDNs[h]; ok {
		return true
	}
	for _, suffix := range []string{".bot-hosting.net", ".bot-hosting.cloud"} {
		if strings.HasSuffix(h, suffix) &&
			!strings.HasSuffix(h, ".apps.bot-hosting.net") &&
			!strings.HasSuffix(h, ".apps.bot-hosting.cloud") &&
			!strings.HasSuffix(h, ".site.bot-hosting.cloud") {
			sub := strings.TrimSuffix(h, suffix)
			if sub != "" && !strings.Contains(sub, ".") {
				return true
			}
		}
	}
	if strings.HasSuffix(h, ".your-server.de") || strings.HasSuffix(h, ".hetzner.com") {
		return true
	}
	return false
}

func isBotHostingCnameAlias(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	if isBotHostingNodeHost(h) {
		return true
	}
	return h == "apps.bot-hosting.cloud" ||
		h == "site.bot-hosting.cloud" ||
		h == "bot-hosting.cloud" ||
		h == "bot-hosting.net"
}

func isBotHostingManagedDomain(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	return isBotHostingCnameAlias(h) ||
		strings.Contains(h, "bot-hosting.cloud") ||
		strings.Contains(h, "bot-hosting.net") ||
		strings.HasSuffix(h, ".cluster.local") ||
		strings.HasSuffix(h, ".svc") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".local")
}

func isBotHostingPublicDomain(h string) bool {
	h = cleanHost(h)
	if h == "" || isBotHostingCnameAlias(h) {
		return false
	}
	return (strings.HasSuffix(h, ".apps.bot-hosting.cloud") ||
		strings.HasSuffix(h, ".site.bot-hosting.cloud")) &&
		!strings.HasSuffix(h, ".internal") &&
		!strings.HasSuffix(h, ".local") &&
		!strings.HasSuffix(h, ".cluster.local") &&
		!strings.HasSuffix(h, ".svc")
}

func isFullBotHostingServiceDomain(h string) bool {
	h = cleanHost(h)
	if h == "" || isBotHostingCnameAlias(h) {
		return false
	}
	for _, suffix := range []string{".apps.bot-hosting.cloud", ".site.bot-hosting.cloud"} {
		if strings.HasSuffix(h, suffix) {
			sub := strings.TrimSuffix(h, suffix)
			return sub != ""
		}
	}
	return false
}

func normalizeRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if reg, ok := knownBotHostingNodeIPs[s]; ok {
		return reg
	}
	switch {
	case strings.HasPrefix(s, "de") || strings.Contains(s, "de-fra") || strings.Contains(s, "frankfurt") || strings.Contains(s, "falkenstein") || strings.Contains(s, "nuremberg") || strings.Contains(s, "germany") || strings.Contains(s, "prem-eu"):
		return "de-fra1"
	case strings.HasPrefix(s, "fi") || strings.Contains(s, "fi-hel") || strings.Contains(s, "helsinki") || strings.Contains(s, "finland") || strings.Contains(s, "hel"):
		return "fi-hel1"
	case strings.Contains(s, "nl-ams") || strings.Contains(s, "europe-west4") || strings.Contains(s, "amsterdam") || strings.Contains(s, "nl"):
		return "europe-west4"
	case strings.Contains(s, "ch-") || strings.Contains(s, "zurich") || strings.Contains(s, "switzerland"):
		return "ch-central"
	case strings.Contains(s, "uk-lon") || strings.Contains(s, "london") || strings.Contains(s, "uk"):
		return "uk-lon1"
	case strings.HasPrefix(s, "us") || strings.Contains(s, "us-east") || strings.Contains(s, "virginia") || strings.Contains(s, "nyc") || strings.Contains(s, "chi"):
		return "us-east4"
	case strings.Contains(s, "us-west") || strings.Contains(s, "california") || strings.Contains(s, "oregon") || strings.Contains(s, "sjc"):
		return "us-west"
	case strings.Contains(s, "sg-sin") || strings.Contains(s, "singapore") || strings.Contains(s, "asia") || strings.Contains(s, "sin"):
		return "asia-southeast1"
	default:
		return "fi-hel1"
	}
}

func resolveContainerPort() (string, int) {
	for _, key := range []string{"SERVER_PORT", "PORT", "BERMUDA_LISTEN_PORT", "APP_PORT"} {
		if raw := strings.TrimSpace(getEnv(key, "")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 65535 {
				return strconv.Itoa(n), n
			}
		}
	}
	return defaultPort, 8080
}

func resolveInfrastructureDomains() (bhDomain, customDomain, nodeHost string) {
	subEnv := cleanHost(getEnv("BOTHOSTING_SUBDOMAIN", getEnv("BOTHOSTING_PUBLIC_DOMAIN", getEnv("BOTHOSTING_DOMAIN", ""))))
	explicitBH := cleanHost(getEnv("BERMUDA_BOTHOSTING_DOMAIN", getEnv("PUBLIC_URL", "")))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))
	nodeEnv := cleanHost(getEnv("BOTHOSTING_NODE_HOST", getEnv("BOTHOSTING_NODE_FQDN", getEnv("P_SERVER_LOCATION", ""))))

	for _, candidate := range []string{subEnv, explicitBH} {
		if isBotHostingPublicDomain(candidate) {
			bhDomain = candidate
			break
		}
	}

	for _, candidate := range []string{customEnv, explicitBH, subEnv} {
		if candidate != "" && !isBotHostingManagedDomain(candidate) {
			customDomain = candidate
			break
		}
	}

	for _, candidate := range []string{nodeEnv, subEnv, explicitBH} {
		if isBotHostingNodeHost(candidate) || (candidate != "" && net.ParseIP(candidate) != nil) {
			nodeHost = resolveNodeHostToIP(candidate)
			break
		}
	}

	return bhDomain, customDomain, nodeHost
}

func generateEphemeralSelfSignedTLS() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		serialNumber = big.NewInt(time.Now().UnixNano())
	}

	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OpenResty Edge Gateway"},
			CommonName:   "openresty.local",
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "*.bot-hosting.cloud", "*.bot-hosting.net"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

type peekedConn struct {
	net.Conn
	r   *bufio.Reader
	tcp *net.TCPConn
}

func (c *peekedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *peekedConn) CloseWrite() error {
	if c.tcp != nil {
		return c.tcp.CloseWrite()
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *peekedConn) SetNoDelay(noDelay bool) error {
	if c.tcp != nil {
		return c.tcp.SetNoDelay(noDelay)
	}
	return nil
}

func (c *peekedConn) UnderlyingTCPConn() *net.TCPConn {
	return c.tcp
}

type dualProtocolListener struct {
	net.Listener
	tlsConfig *tls.Config
}

func newDualProtocolListener(inner net.Listener, tlsCfg *tls.Config) net.Listener {
	if tlsCfg == nil {
		return inner
	}
	return &dualProtocolListener{
		Listener:  inner,
		tlsConfig: tlsCfg,
	}
}

func (l *dualProtocolListener) Accept() (net.Conn, error) {
	rawConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	var tcpConn *net.TCPConn
	if tc, ok := rawConn.(*net.TCPConn); ok {
		tcpConn = tc
		_ = tc.SetNoDelay(true)
	}

	br := bufio.NewReaderSize(rawConn, 4096)
	_ = rawConn.SetReadDeadline(time.Now().Add(firstBytePeekTimeout))
	hdr, peekErr := br.Peek(1)
	_ = rawConn.SetReadDeadline(time.Time{})

	pc := &peekedConn{
		Conn: rawConn,
		r:    br,
		tcp:  tcpConn,
	}

	if peekErr == nil && len(hdr) == 1 && hdr[0] == 0x16 {
		return tls.Server(pc, l.tlsConfig), nil
	}

	return pc, nil
}

func bindDualListeners(listenCfg *net.ListenConfig, primaryPort string, tlsCfg *tls.Config) ([]net.Listener, []string, error) {
	strictMode := strings.EqualFold(getEnv("BERMUDA_STRICT_PORT", "false"), "true")

	seenPorts := make(map[string]struct{}, 3)
	var portsToTry []string
	addPort := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, exists := seenPorts[p]; !exists {
			seenPorts[p] = struct{}{}
			portsToTry = append(portsToTry, p)
		}
	}

	addPort(primaryPort)
	if !strictMode {
		addPort(defaultPort)
		addPort(compatAltPort)
	}

	var listeners []net.Listener
	var boundAddrs []string
	var firstErr error

	for i, p := range portsToTry {
		addr := "0.0.0.0:" + p
		ln, err := listenCfg.Listen(context.Background(), "tcp", addr)
		if err != nil {
			if i == 0 {
				firstErr = err
				if strictMode {
					return nil, nil, err
				}
				log.Printf("[Gateway] Notice: Primary port :%s unavailable (%v); binding compatibility ports...", p, err)
			}
			continue
		}
		listeners = append(listeners, newDualProtocolListener(ln, tlsCfg))
		boundAddrs = append(listenersAddr(boundAddrs, ":"+p)...)
	}

	if len(listeners) == 0 {
		return nil, nil, firstErr
	}
	return listeners, boundAddrs, nil
}

func listenersAddr(existing []string, addr string) []string {
	return append(existing, addr)
}

func orchestrateCloudInfrastructure(
	ctx context.Context,
	sup *Supervisor,
	gw *Gateway,
	bh *BotHostingClient,
	cf *CloudflareClient,
	initialBH string,
	initialCF string,
	initialNode string,
	initialPort int,
	region string,
) {
	for i := 0; i < 120 && !sup.IsReady(); i++ {
		if !sleepContext(ctx, 250*time.Millisecond) {
			return
		}
	}

	if !sleepContext(ctx, startupOrchestrationDelay) {
		return
	}

	bhDomain := cleanHost(initialBH)
	customDomain := cleanHost(initialCF)
	nodeHost := resolveNodeHostToIP(initialNode)
	containerPort := initialPort

	if curBH, curCF, _ := sup.GetInfrastructureDomains(); bhDomain == "" || customDomain == "" {
		if bhDomain == "" && isBotHostingPublicDomain(curBH) {
			bhDomain = curBH
		}
		if customDomain == "" && curCF != "" && !isBotHostingManagedDomain(curCF) {
			customDomain = curCF
		}
	}
	if curNode, curPort := sup.GetNodeEndpoint(); nodeHost == "" || containerPort <= 0 {
		if nodeHost == "" && curNode != "" {
			nodeHost = resolveNodeHostToIP(curNode)
		}
		if containerPort <= 0 && curPort > 0 {
			containerPort = curPort
		}
	}

	topologyUpdated := false
	loggedAfterDiscovery := false

	syncDomains := func(newBH, newCF, newNode string, newPort int) {
		cleanBH := cleanHost(newBH)
		cleanCF := cleanHost(newCF)
		cleanNode := resolveNodeHostToIP(newNode)

		if isBotHostingPublicDomain(cleanBH) {
			if bhDomain == "" || (!isFullBotHostingServiceDomain(bhDomain) && isFullBotHostingServiceDomain(cleanBH)) {
				if bhDomain != cleanBH {
					bhDomain = cleanBH
					topologyUpdated = true
				}
			}
		}
		if cleanCF != "" && !isBotHostingManagedDomain(cleanCF) {
			if customDomain == "" || strings.HasSuffix(cleanCF, "."+customDomain) {
				if customDomain != cleanCF {
					customDomain = cleanCF
					topologyUpdated = true
				}
			}
		}
		if cleanNode != "" && (isBotHostingNodeHost(cleanNode) || net.ParseIP(cleanNode) != nil) {
			if nodeHost != cleanNode {
				nodeHost = cleanNode
				topologyUpdated = true
			}
		}
		if newPort > 0 && newPort != containerPort {
			containerPort = newPort
			topologyUpdated = true
		}

		sup.SetInfrastructureDomains(bhDomain, customDomain, region)
		sup.SetNodeEndpoint(nodeHost, containerPort)
		gw.SetInfrastructureDomains(bhDomain, customDomain, region)
		gw.SetNodeEndpoint(nodeHost, containerPort)

		if cf != nil {
			if bhDomain != "" {
				cf.SetBotHostingOrigin(bhDomain)
			}
			if nodeHost != "" || containerPort > 0 {
				cf.SetBotHostingNodeOrigin(nodeHost, containerPort)
			}
			if customDomain != "" {
				cf.SetPreferredDomain(customDomain)
			}
		}
		if bh != nil {
			if bhDomain != "" {
				bh.SetServiceDomain(bhDomain)
			}
			if customDomain != "" {
				bh.SetCustomDomain(customDomain)
			}
			if nodeHost != "" || containerPort > 0 {
				bh.SetNodeEndpoint(nodeHost, containerPort)
			}
		}
	}

	if bh != nil && bh.IsConfigured() {
		if srvDom, err := bh.EnsureServiceDomain(ctx); err == nil && srvDom != "" {
			syncDomains(srvDom, "", bh.GetNodeHost(), bh.GetTargetPort())
		} else if err != nil {
			log.Printf("[BotHosting] Notice: Deployment topology lookup: %v", err)
		}

		if discNode := bh.GetNodeHost(); discNode != "" {
			syncDomains(bh.GetServiceDomain(), bh.GetCustomDomain(), discNode, bh.GetTargetPort())
		}

		if reg := bh.GetDiscoveredRegion(); reg != "" {
			region = normalizeRegion(reg)
			sup.SetInfrastructureDomains(bhDomain, customDomain, region)
			gw.SetInfrastructureDomains(bhDomain, customDomain, region)
		}

		if sup.IsMasterKeyAutoGenerated() && !strings.EqualFold(getEnv("BERMUDA_PERSIST_KEY", "true"), "false") {
			bh.PersistMasterKey(ctx, sup.MasterKey())
			if !sleepContext(ctx, 1500*time.Millisecond) {
				return
			}
		}
	}

	if cf != nil && cf.Token != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		if cfDom, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDom != "" {
			discNode, discPort := cf.GetBotHostingNodeOrigin()
			syncDomains(cf.GetBotHostingOrigin(), cfDom, discNode, discPort)
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()
	}

	if topologyUpdated && ctx.Err() == nil {
		log.Printf("[Runtime] Synchronized Topology: BotHostingDomain=%q | CloudflareDomain=%q | Node=%s:%d | Region=%q",
			bhDomain, customDomain, nodeHost, containerPort, region)
		sup.LogProvisioningLink("")
		loggedAfterDiscovery = true
	}

	var customDomInfo *BotHostingCustomDomainInfo
	var cnameRecordID string
	var cfDNSProvisioned bool

	if customDomain != "" {
		if nodeHost != "" && containerPort > 0 {
			customDomInfo = &BotHostingCustomDomainInfo{
				Domain:            customDomain,
				CNAMETarget:       nodeHost,
				OriginPort:        containerPort,
				DirectNodeMode:    true,
				CertificateStatus: "VALID",
				RecordsVerified:   true,
			}
		} else if bh != nil && bh.IsConfigured() {
			info, err := bh.EnsureCustomDomain(ctx, customDomain)
			if err != nil {
				log.Printf("[BotHosting] Notice: Custom domain registration (%s): %v", customDomain, err)
			} else if info != nil {
				customDomInfo = info
				syncDomains(bh.GetServiceDomain(), info.Domain, bh.GetNodeHost(), bh.GetTargetPort())
			}
		}

		if customDomInfo == nil && bhDomain != "" {
			customDomInfo = &BotHostingCustomDomainInfo{
				Domain:            customDomain,
				CNAMETarget:       bhDomain,
				OriginPort:        443,
				DirectNodeMode:    true,
				CertificateStatus: "VALID",
				RecordsVerified:   true,
			}
		}

		if customDomInfo != nil && cf != nil && cf.Token != "" {
			recID, dnsErr := cf.ProvisionBotHostingDNS(ctx, customDomInfo)
			if dnsErr != nil {
				log.Printf("[Cloudflare] Warning: Automated Bot-Hosting DNS provisioning: %v", dnsErr)
			} else {
				cnameRecordID = recID
				cfDNSProvisioned = true
				_ = sleepContext(ctx, dnsPropagationSettleDelay)
			}
		}
	}

	if cf != nil && cf.Token != "" && ctx.Err() == nil {
		cf.Tune(ctx)
		discNode, discPort := cf.GetBotHostingNodeOrigin()
		syncDomains(cf.GetBotHostingOrigin(), cf.CachedZoneDomain(), discNode, discPort)
	}

	autoOrange := !strings.EqualFold(getEnv("BERMUDA_CF_AUTO_ORANGE", "true"), "false")
	if cf != nil && customDomInfo != nil && !customDomInfo.IsCertificateValid() && autoOrange && ctx.Err() == nil {
		if cfDNSProvisioned || customDomInfo.RecordsVerified {
			log.Printf("[BotHosting] Waiting for Custom Domain TLS verification on %s before enabling Cloudflare Orange Cloud...", customDomInfo.Domain)
			if bh != nil && bh.IsConfigured() {
				updatedInfo, valid := bh.WaitCustomDomainCertificate(ctx, customDomInfo.ID, customDomInfo.Domain, defaultBHCertPollWait)
				if valid && updatedInfo != nil {
					cf.PromoteCustomDomainToOrangeCloud(ctx, updatedInfo.Domain, updatedInfo.CNAMETarget, cnameRecordID)
				} else if ctx.Err() == nil {
					go watchAndPromoteCustomDomain(ctx, bh, cf, customDomInfo, cnameRecordID)
				}
			}
		}
	}

	if bh != nil && bh.IsConfigured() && ctx.Err() == nil {
		bh.TuneComputeAndNetwork(ctx)
	}

	if ctx.Err() == nil && !loggedAfterDiscovery && (topologyUpdated || bh != nil || cf != nil) {
		log.Printf("[Runtime] Synchronized Topology: BotHostingDomain=%q | CloudflareDomain=%q | Node=%s:%d | Region=%q",
			bhDomain, customDomain, nodeHost, containerPort, region)
		sup.LogProvisioningLink("")
	}
}

func watchAndPromoteCustomDomain(
	parent context.Context,
	bh *BotHostingClient,
	cf *CloudflareClient,
	info *BotHostingCustomDomainInfo,
	cnameRecordID string,
) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if bh != nil && bh.IsConfigured() {
				latest, err := bh.FetchCustomDomainStatus(ctx, info.ID, info.Domain)
				if err == nil && latest != nil && latest.IsCertificateValid() {
					log.Printf("[BotHosting] ✓ Deferred Custom Domain TLS verified for %s (%s)",
						latest.Domain, latest.CertificateStatus)
					cf.PromoteCustomDomainToOrangeCloud(ctx, latest.Domain, latest.CNAMETarget, cnameRecordID)
					return
				}
			}
		}
	}
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cloudCancel context.CancelFunc,
	graceful bool,
) {
	hardDeadline := time.Now().Add(18 * time.Second)

	if cloudCancel != nil {
		cloudCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status set to 503 (traffic shedding)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP/TLS listeners and active XHTTP streams...")
		httpDeadline := minTime(hardDeadline.Add(-6*time.Second), time.Now().Add(10*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP drain timeout (%v); closing listeners", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP/TLS listeners drained cleanly")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active upgraded WebSocket tunnels...")
		tunnelDeadline := minTime(hardDeadline.Add(-5*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Closing remaining sockets and idle pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Stopping worker process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("[Gateway] Initializing BERMUDA PORTAL Edge Router (Bot-Hosting.net + Cloudflare Edition)...")

	gwMB, workerMB, compact := deriveMemoryBudget()
	procs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_WORKER_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_XRAY_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_WORKER_GOMAXPROCS", strconv.Itoa(procs))
	_ = syscall.Setenv("BERMUDA_XRAY_GOMAXPROCS", strconv.Itoa(procs))

	tierLabel := "STANDARD"
	if compact {
		tierLabel = "COMPACT-256MB-SAFE"
	}
	log.Printf("[Runtime] Resource budget calibrated [%s]: Gateway=%dMiB, Worker=%dMiB | GOMAXPROCS=%d",
		tierLabel, gwMB, workerMB, procs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	portStr, portNum := resolveContainerPort()
	bhDomain, customDomain, nodeHost := resolveInfrastructureDomains()

	rawRegion := getEnv("BERMUDA_REGION", getEnv("BOTHOSTING_REGION", getEnv("REGION", "")))
	if rawRegion == "" && nodeHost != "" {
		rawRegion = nodeHost
	}
	region := normalizeRegion(rawRegion)

	sup := NewSupervisor()
	sup.SetNodeEndpoint(nodeHost, portNum)

	cfToken := sanitizeCloudflareToken(getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", "")))
	cfZoneID := sanitizeExplicitCredential(getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", "")))
	var cf *CloudflareClient
	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if bhDomain != "" {
			cf.SetBotHostingOrigin(bhDomain)
		}
		if nodeHost != "" || portNum > 0 {
			cf.SetBotHostingNodeOrigin(nodeHost, portNum)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}
	} else {
		log.Println("[Cloudflare] Notice: CLOUDFLARE_API_TOKEN unset. Edge auto-tuning bypassed.")
	}

	bhToken := sanitizeBotHostingToken(getEnv("BOTHOSTING_API_KEY", getEnv("BOTHOSTING_API_TOKEN", getEnv("BOTHOSTING_TOKEN", getEnv("BERMUDA_BOTHOSTING_TOKEN", "")))))
	var bh *BotHostingClient
	if bhToken != "" {
		bh = NewBotHostingClient(bhToken)
		if bhDomain != "" {
			bh.SetServiceDomain(bhDomain)
		}
		if customDomain != "" {
			bh.SetCustomDomain(customDomain)
		}
		if nodeHost != "" || portNum > 0 {
			bh.SetNodeEndpoint(nodeHost, portNum)
		}
	} else {
		log.Println("[BotHosting] Notice: BOTHOSTING_API_KEY unset. Bot-Hosting API self-provisioning bypassed.")
	}

	sup.SetInfrastructureDomains(bhDomain, customDomain, region)
	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = bhDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	log.Printf("[Runtime] Initial Topology: BotHostingDomain=%q | CloudflareDomain=%q | Node=%s:%d | Region=%q",
		bhDomain, customDomain, nodeHost, portNum, region)

	gw := NewGateway(sup, cf, bhDomain, customDomain, region)
	gw.SetBotHostingClient(bh)
	gw.SetNodeEndpoint(nodeHost, portNum)

	topologyUpdater := func(bhDom, cfDom string) {
		sup.SetInfrastructureDomains(bhDom, cfDom, region)
		gw.SetInfrastructureDomains(bhDom, cfDom, region)
	}
	if cf != nil {
		cf.SetTopologyCallback(topologyUpdater)
	}
	if bh != nil {
		bh.SetTopologyCallback(topologyUpdater)
	}

	tlsCfg, tlsErr := generateEphemeralSelfSignedTLS()
	if tlsErr != nil {
		log.Printf("[Gateway] Warning: Could not generate ephemeral TLS certificate (%v); serving plain HTTP only", tlsErr)
	}

	maxHdrBytes := 32 << 10
	if compact {
		maxHdrBytes = 16 << 10
	}

	srv := &http.Server{
		Addr:              "0.0.0.0:" + portStr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       12 * time.Minute,
		MaxHeaderBytes:    maxHdrBytes,
		ConnState:         gw.TrackConnState,
	}

	listenCfg := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000)
			})
			return nil
		},
	}

	listeners, boundAddrs, err := bindDualListeners(&listenCfg, portStr, tlsCfg)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind listener on :%s: %v", portStr, err)
	}

	serverErrCh := make(chan error, len(listeners))
	log.Printf("[Gateway] Dual-Protocol (TLS 1.3 + HTTP) listeners active on %s (PID %d, GOMAXPROCS=%d)",
		strings.Join(boundAddrs, " & "), os.Getpid(), procs)

	for _, ln := range listeners {
		activeLn := ln
		go func() {
			if err := srv.Serve(activeLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case serverErrCh <- err:
				default:
				}
			}
		}()
	}

	supCtx, supCancel := context.WithCancel(context.Background())
	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	go func() {
		select {
		case <-sup.BootstrapDone():
		case <-sigCtx.Done():
			return
		}
		runtime.GC()
		debug.FreeOSMemory()
		applyMemoryCeiling(gwMB, compact)
	}()

	cloudCtx, cloudCancel := context.WithCancel(sigCtx)
	defer cloudCancel()
	if bh != nil || cf != nil {
		go orchestrateCloudInfrastructure(cloudCtx, sup, gw, bh, cf, bhDomain, customDomain, nodeHost, portNum, region)
	}

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP/TLS server error: %v", err)
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Worker supervisor halted: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal received. Initiating graceful teardown...")
	}

	teardown(srv, gw, sup, supCancel, cloudCancel, true)
	log.Println("[Gateway] BERMUDA PORTAL Edge Router shutdown complete. Exit 0.")
}
