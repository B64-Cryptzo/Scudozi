package scanner

import (
	"bufio"
	"errors"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const (
	BindScopeLocalhostOnly = "localhost_only"
	BindScopeLANOnly       = "lan_only"
	BindScopeVirtualOnly   = "virtual_only"
	BindScopeAllInterfaces = "all_interfaces"
	BindScopePublicIPBound = "public_ip_bound"
	BindScopeUnknown       = "unknown"
)

const (
	ReachabilityLocalOnly         = "local_only"
	ReachabilityLANReachable      = "lan_reachable"
	ReachabilityPotentialExternal = "potentially_external"
	ReachabilityPublicInterface   = "public_interface"
	ReachabilityUnknown           = "unknown"
)

type Service struct {
	RawAddress         string `json:"raw_address"`
	Host               string `json:"host"`
	Port               string `json:"port"`
	Process            string `json:"process"`
	PID                int    `json:"pid"`
	BindScope          string `json:"bind_scope"`
	LikelyReachability string `json:"likely_reachability"`
	InterfaceType      string `json:"interface_type"`
	Exposed            bool   `json:"exposed"`
	NodeName           string `json:"node_name"`
	Status             string `json:"status"`
}

type interfaceIndex struct {
	byAddress map[string]string
}

func ScanPorts() ([]Service, error) {
	idx := buildInterfaceIndex()

	switch runtime.GOOS {
	case "windows":
		return scanWindows(idx)
	case "linux":
		return scanLinux(idx)
	case "darwin":
		return scanDarwin(idx)
	default:
		return nil, errors.New("unsupported operating system: " + runtime.GOOS)
	}
}

func scanWindows(idx interfaceIndex) ([]Service, error) {
	out, err := exec.Command("netstat", "-ano", "-p", "tcp").Output()
	if err != nil {
		return nil, errors.New("windows netstat failed: " + err.Error())
	}

	pidMap := loadWindowsProcessNames()

	var services []Service
	sc := bufio.NewScanner(strings.NewReader(string(out)))

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "TCP") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		localAddr := fields[1]
		state := fields[3]
		pid := fields[4]

		if state != "LISTENING" {
			continue
		}

		host, port := splitAddr(localAddr)
		process := pidMap[pid]
		if process == "" {
			process = "pid-" + pid
		}

		services = append(services, buildService(localAddr, host, port, process, parsePID(pid), idx))
	}

	return services, nil
}

func scanLinux(idx interfaceIndex) ([]Service, error) {
	if out, err := exec.Command("ss", "-ltnp").Output(); err == nil {
		return parseSS(string(out), idx), nil
	}

	if out, err := exec.Command("netstat", "-ltnp").Output(); err == nil {
		return parseLinuxNetstat(string(out), idx), nil
	}

	return nil, errors.New("linux scan failed: neither ss nor netstat was available")
}

func scanDarwin(idx interfaceIndex) ([]Service, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:LISTEN").Output()
	if err != nil {
		return nil, errors.New("macOS lsof failed: " + err.Error())
	}

	return parseLsof(string(out), idx), nil
}

func loadWindowsProcessNames() map[string]string {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return map[string]string{}
	}

	result := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		parts := parseCSVLine(line)
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		pid := parts[1]
		result[pid] = name
	}

	return result
}

func parseSS(raw string, idx interfaceIndex) []Service {
	var services []Service
	sc := bufio.NewScanner(strings.NewReader(raw))

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "State") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		addr := fields[3]
		process := fields[len(fields)-1]

		host, port := splitAddr(addr)
		services = append(services, buildService(addr, host, port, process, parsePIDFromToken(process), idx))
	}

	return services
}

func parseLinuxNetstat(raw string, idx interfaceIndex) []Service {
	var services []Service
	sc := bufio.NewScanner(strings.NewReader(raw))

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Proto") || strings.HasPrefix(line, "Active") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		state := fields[5]
		if state != "LISTEN" {
			continue
		}

		addr := fields[3]
		process := ""
		if len(fields) >= 7 {
			process = fields[6]
		}

		host, port := splitAddr(addr)
		services = append(services, buildService(addr, host, port, process, parsePIDFromToken(process), idx))
	}

	return services
}

func parseLsof(raw string, idx interfaceIndex) []Service {
	var services []Service
	sc := bufio.NewScanner(strings.NewReader(raw))

	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		if first {
			first = false
			if strings.HasPrefix(line, "COMMAND") {
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		process := fields[0]
		nameField := fields[len(fields)-1]

		host, port := splitAddr(nameField)
		pid := parsePID(fields[1])
		services = append(services, buildService(nameField, host, port, process, pid, idx))
	}

	return services
}

func buildService(rawAddr, host, port, process string, pid int, idx interfaceIndex) Service {
	bindScope, reachability, ifaceType := classifyAddress(host, idx)
	status := statusFromClassification(bindScope, reachability)
	if process == "" {
		process = "unknown"
	}

	nodeName := process + "@" + host + ":" + port
	if host == "" {
		nodeName = process + ":" + port
	}

	return Service{
		RawAddress:         rawAddr,
		Host:               host,
		Port:               port,
		Process:            process,
		PID:                pid,
		BindScope:          bindScope,
		LikelyReachability: reachability,
		InterfaceType:      ifaceType,
		Exposed:            reachability != ReachabilityLocalOnly,
		NodeName:           nodeName,
		Status:             status,
	}
}

func parsePID(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func parsePIDFromToken(token string) int {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0
	}

	// netstat format: "1234/python"
	if slash := strings.Index(token, "/"); slash > 0 {
		return parsePID(token[:slash])
	}

	// ss format often includes "pid=1234"
	if i := strings.Index(token, "pid="); i >= 0 {
		sub := token[i+4:]
		end := len(sub)
		for j, ch := range sub {
			if ch < '0' || ch > '9' {
				end = j
				break
			}
		}
		return parsePID(sub[:end])
	}

	return parsePID(token)
}

func classifyAddress(host string, idx interfaceIndex) (bindScope, likelyReachability, interfaceType string) {
	normalized := normalizeHost(host)
	ifaceType := idx.byAddress[normalized]
	if ifaceType == "" {
		ifaceType = "unknown"
	}

	if isAllInterfacesHost(normalized) {
		return BindScopeAllInterfaces, ReachabilityPotentialExternal, "all_interfaces"
	}

	if isLoopbackHost(normalized) {
		return BindScopeLocalhostOnly, ReachabilityLocalOnly, "loopback"
	}

	ip := parseIP(normalized)
	if ip == nil {
		return BindScopeUnknown, ReachabilityUnknown, ifaceType
	}

	if ip.IsLoopback() {
		return BindScopeLocalhostOnly, ReachabilityLocalOnly, "loopback"
	}

	if isPublicIP(ip) {
		if ifaceType == "unknown" {
			ifaceType = "public"
		}
		return BindScopePublicIPBound, ReachabilityPublicInterface, ifaceType
	}

	if ifaceType == "virtual" || likelyVirtualRange(ip) {
		return BindScopeVirtualOnly, ReachabilityUnknown, "virtual"
	}

	if isRFC1918(ip) {
		if ifaceType == "unknown" {
			ifaceType = "lan"
		}
		return BindScopeLANOnly, ReachabilityLANReachable, ifaceType
	}

	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return BindScopeUnknown, ReachabilityUnknown, ifaceType
	}

	return BindScopeUnknown, ReachabilityUnknown, ifaceType
}

func statusFromClassification(bindScope, reachability string) string {
	if bindScope == BindScopeVirtualOnly {
		return "virtual"
	}

	switch reachability {
	case ReachabilityLocalOnly:
		return "local"
	case ReachabilityLANReachable:
		return "lan"
	case ReachabilityPotentialExternal:
		return "potential"
	case ReachabilityPublicInterface:
		return "public"
	default:
		return "unknown"
	}
}

func splitAddr(addr string) (string, string) {
	addr = strings.TrimSpace(addr)
	if strings.HasSuffix(addr, "(LISTEN)") {
		addr = strings.TrimSpace(strings.TrimSuffix(addr, "(LISTEN)"))
	}

	host := addr
	port := ""

	if strings.HasPrefix(addr, "[") {
		end := strings.LastIndex(addr, "]:")
		if end != -1 {
			host = addr[1:end]
			port = addr[end+2:]
			return normalizeHost(host), port
		}
	}

	i := strings.LastIndex(addr, ":")
	if i == -1 {
		return normalizeHost(host), port
	}

	host = addr[:i]
	port = addr[i+1:]
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return normalizeHost(host), port
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

func isAllInterfacesHost(host string) bool {
	switch host {
	case "", "*", "0.0.0.0", "::":
		return true
	default:
		return false
	}
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

func parseIP(host string) net.IP {
	if host == "" {
		return nil
	}
	return net.ParseIP(host)
}

func isRFC1918(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4[0] == 10 {
		return true
	}
	if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
		return true
	}
	if v4[0] == 192 && v4[1] == 168 {
		return true
	}
	return false
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	if isRFC1918(ip) {
		return false
	}
	if ip.To4() != nil {
		v4 := ip.To4()
		if v4[0] == 169 && v4[1] == 254 {
			return false
		}
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		if v4[0] >= 224 {
			return false
		}
		return true
	}
	if len(ip) == net.IPv6len {
		if ip[0]&0xfe == 0xfc {
			return false
		}
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return false
		}
		if ip.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

func likelyVirtualRange(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
			return true
		}
		return false
	}

	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	if v4[0] == 192 && v4[1] == 168 && (v4[2] == 56 || v4[2] == 122) {
		return true
	}
	if v4[0] == 10 && v4[1] == 0 && v4[2] == 75 {
		return true
	}
	if v4[0] == 172 && v4[1] >= 17 && v4[1] <= 31 {
		return true
	}
	return false
}

func buildInterfaceIndex() interfaceIndex {
	idx := interfaceIndex{byAddress: map[string]string{}}

	interfaces, err := net.Interfaces()
	if err != nil {
		return idx
	}

	for _, ifc := range interfaces {
		ifType := classifyInterfaceType(ifc)
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			host := interfaceAddressHost(addr)
			if host == "" {
				continue
			}
			idx.byAddress[host] = ifType
		}
	}

	return idx
}

func classifyInterfaceType(ifc net.Interface) string {
	name := strings.ToLower(ifc.Name)
	if ifc.Flags&net.FlagLoopback != 0 {
		return "loopback"
	}

	virtualHints := []string{
		"vethernet", "hyper-v", "hyperv", "vmware", "vbox", "virtual", "docker", "wsl", "tailscale",
		"zerotier", "wireguard", "tun", "tap", "vpn", "ppp",
	}
	for _, hint := range virtualHints {
		if strings.Contains(name, hint) {
			return "virtual"
		}
	}

	if ifc.Flags&net.FlagUp != 0 {
		return "lan"
	}
	return "unknown"
}

func interfaceAddressHost(addr net.Addr) string {
	switch v := addr.(type) {
	case *net.IPNet:
		return normalizeHost(v.IP.String())
	case *net.IPAddr:
		return normalizeHost(v.IP.String())
	default:
		return ""
	}
}

func parseCSVLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	var parts []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(line); i++ {
		ch := line[i]

		switch ch {
		case '"':
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				current.WriteByte('"')
				i++
				continue
			}
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				current.WriteByte(ch)
			} else {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}

	parts = append(parts, current.String())
	return parts
}
