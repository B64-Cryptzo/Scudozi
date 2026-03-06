package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"scudozi/graph"
	"scudozi/scanner"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type errorResponse struct {
	Error string `json:"error"`
}

var (
	demoKilledMu       sync.Mutex
	demoKilledServices = map[string]bool{}
	startedAt          = time.Now().UTC()
	version            = "dev"
	commit             = "unknown"
	buildDate          = "unknown"
)

func graphHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	services, err := scanner.ScanPorts()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
		return
	}
	if demoServicesEnabled() {
		services = append(services, buildDemoServices(demoServicesCount())...)
	}

	nodes := []graph.Node{
		{
			ID:                 "internet",
			Label:              "External Reachability",
			Status:             "neutral",
			BindScope:          "unknown",
			LikelyReachability: "unknown",
			InterfaceType:      "informational",
		},
	}
	edges := []graph.Edge{}
	seenNodeIDs := map[string]int{}

	for _, s := range services {
		id := fmt.Sprintf("%s|%s|%s|%s", s.Process, s.Host, s.Port, s.RawAddress)
		seenNodeIDs[id]++
		if seenNodeIDs[id] > 1 {
			id = fmt.Sprintf("%s#%d", id, seenNodeIDs[id])
		}

		nodes = append(nodes, graph.Node{
			ID:                 id,
			Label:              s.NodeName,
			Status:             s.Status,
			PID:                s.PID,
			RawAddress:         s.RawAddress,
			Host:               s.Host,
			Port:               s.Port,
			Process:            s.Process,
			BindScope:          s.BindScope,
			LikelyReachability: s.LikelyReachability,
			InterfaceType:      s.InterfaceType,
			Exposed:            s.Exposed,
		})

		if s.Exposed {
			edges = append(edges, graph.Edge{
				From: "internet",
				To:   id,
			})
		}
	}

	response := struct {
		OS    string      `json:"os"`
		Graph graph.Graph `json:"graph"`
	}{
		OS: runtime.GOOS,
		Graph: graph.Graph{
			Nodes: nodes,
			Edges: edges,
		},
	}

	_ = json.NewEncoder(w).Encode(response)
}

type killProcessRequest struct {
	PID         int    `json:"pid"`
	Process     string `json:"process"`
	StepupToken string `json:"stepup_token"`
}

func killProcessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req killProcessRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	sess := mustSessionFromContext(r)
	if !validateStepupToken(sess.Username, sess.Role, req.StepupToken) {
		logAudit("process.kill.stepup", sess.Username, sess.Role, "denied", map[string]any{"reason": "stepup_invalid", "pid": req.PID})
		http.Error(w, "step-up verification required", http.StatusUnauthorized)
		return
	}
	if req.PID <= 0 {
		http.Error(w, "pid unavailable for selected process", http.StatusBadRequest)
		return
	}
	if isDemoServiceProcess(req.Process) {
		markDemoServiceKilled(req.Process)
		logAudit("process.kill", sess.Username, sess.Role, "success", map[string]any{
			"pid":       req.PID,
			"process":   req.Process,
			"simulated": true,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": fmt.Sprintf("Simulated termination of demo process %s (pid %d)", req.Process, req.PID),
		})
		return
	}
	resolvedProcess, verified, err := validateKillTarget(req.PID, req.Process)
	if err != nil {
		logAudit("process.kill", sess.Username, sess.Role, "error", map[string]any{"pid": req.PID, "process": req.Process, "error": err.Error()})
		http.Error(w, "failed to validate kill target", http.StatusInternalServerError)
		return
	}
	if !verified {
		logAudit("process.kill", sess.Username, sess.Role, "denied", map[string]any{"pid": req.PID, "process": req.Process, "reason": "target_verification_failed"})
		http.Error(w, "kill target verification failed", http.StatusForbidden)
		return
	}
	if isProtectedProcess(req.PID, resolvedProcess) {
		logAudit("process.kill", sess.Username, sess.Role, "denied", map[string]any{"pid": req.PID, "process": req.Process, "reason": "protected_process"})
		http.Error(w, "refusing to terminate protected Scudozi process", http.StatusForbidden)
		return
	}
	if err := killPID(req.PID); err != nil {
		logAudit("process.kill", sess.Username, sess.Role, "error", map[string]any{"pid": req.PID, "process": resolvedProcess, "error": err.Error()})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logAudit("process.kill", sess.Username, sess.Role, "success", map[string]any{"pid": req.PID, "process": resolvedProcess})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": fmt.Sprintf("Terminated %s (pid %d)", resolvedProcess, req.PID),
	})
}

func killPID(pid int) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/F")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("taskkill failed: %s", string(out))
		}
		return nil
	default:
		cmd := exec.Command("kill", "-9", strconv.Itoa(pid))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("kill failed: %s", string(out))
		}
		return nil
	}
}

func isProtectedProcess(pid int, process string) bool {
	if pid == os.Getpid() || pid <= 1 {
		return true
	}
	p := strings.ToLower(strings.TrimSpace(process))
	return strings.Contains(p, "scudozi") || strings.Contains(p, ".scudozi-wrappe")
}

func validateKillTarget(pid int, requestedProcess string) (string, bool, error) {
	services, err := scanner.ScanPorts()
	if err != nil {
		return "", false, err
	}
	for _, s := range services {
		if s.PID != pid {
			continue
		}
		if requestedProcess != "" && !processNamesMatch(requestedProcess, s.Process) {
			return "", false, nil
		}
		return s.Process, true, nil
	}
	return "", false, nil
}

func processNamesMatch(a, b string) bool {
	na := strings.ToLower(strings.TrimSpace(a))
	nb := strings.ToLower(strings.TrimSpace(b))
	if na == nb {
		return true
	}
	return strings.Contains(na, nb) || strings.Contains(nb, na)
}

func isDemoServiceProcess(process string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(process)), "demo-")
}

func markDemoServiceKilled(process string) {
	key := strings.ToLower(strings.TrimSpace(process))
	demoKilledMu.Lock()
	demoKilledServices[key] = true
	demoKilledMu.Unlock()
}

func demoServicesEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SCUDOZI_DEMO_SERVICES")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func demoServicesCount() int {
	v := strings.TrimSpace(os.Getenv("SCUDOZI_DEMO_SERVICES_COUNT"))
	if v == "" {
		return 4
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 4
	}
	if n > 8 {
		return 8
	}
	return n
}

func buildDemoServices(count int) []scanner.Service {
	base := []scanner.Service{
		{
			RawAddress:         "127.0.0.1:3000",
			Host:               "127.0.0.1",
			Port:               "3000",
			Process:            "demo-local-ui",
			PID:                9101,
			BindScope:          "localhost_only",
			LikelyReachability: "local_only",
			InterfaceType:      "loopback",
			Exposed:            false,
			NodeName:           "demo-local-ui@127.0.0.1:3000",
			Status:             "local",
		},
		{
			RawAddress:         "192.168.1.25:9090",
			Host:               "192.168.1.25",
			Port:               "9090",
			Process:            "demo-lan-api",
			PID:                9102,
			BindScope:          "lan_only",
			LikelyReachability: "lan_reachable",
			InterfaceType:      "lan",
			Exposed:            true,
			NodeName:           "demo-lan-api@192.168.1.25:9090",
			Status:             "lan",
		},
		{
			RawAddress:         "0.0.0.0:8000",
			Host:               "0.0.0.0",
			Port:               "8000",
			Process:            "demo-all-iface",
			PID:                9103,
			BindScope:          "all_interfaces",
			LikelyReachability: "potentially_external",
			InterfaceType:      "all_interfaces",
			Exposed:            true,
			NodeName:           "demo-all-iface@0.0.0.0:8000",
			Status:             "potential",
		},
		{
			RawAddress:         "198.51.100.44:443",
			Host:               "198.51.100.44",
			Port:               "443",
			Process:            "demo-public-edge",
			PID:                9104,
			BindScope:          "public_ip_bound",
			LikelyReachability: "public_interface",
			InterfaceType:      "public",
			Exposed:            true,
			NodeName:           "demo-public-edge@198.51.100.44:443",
			Status:             "public",
		},
		{
			RawAddress:         "172.23.64.1:2375",
			Host:               "172.23.64.1",
			Port:               "2375",
			Process:            "demo-virtual-daemon",
			PID:                9105,
			BindScope:          "virtual_only",
			LikelyReachability: "unknown",
			InterfaceType:      "virtual",
			Exposed:            true,
			NodeName:           "demo-virtual-daemon@172.23.64.1:2375",
			Status:             "virtual",
		},
	}
	visible := make([]scanner.Service, 0, len(base))
	demoKilledMu.Lock()
	defer demoKilledMu.Unlock()
	for _, svc := range base {
		if demoKilledServices[strings.ToLower(strings.TrimSpace(svc.Process))] {
			continue
		}
		visible = append(visible, svc)
	}
	if count >= len(visible) {
		return visible
	}
	return visible[:count]
}

func Run() error {
	if err := initAuth(); err != nil {
		return fmt.Errorf("auth init failed: %w", err)
	}

	siteDir := os.Getenv("SCUDOZI_SITE_DIR")
	if strings.TrimSpace(siteDir) == "" {
		siteDir = "site"
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(siteDir)))
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", readyHandler)
	mux.HandleFunc("/version", versionHandler)
	mux.HandleFunc("/graph", authRequired(graphHandler))
	mux.HandleFunc("/auth/srp/start", handleSRPStart)
	mux.HandleFunc("/auth/srp/verify", handleSRPVerify)
	mux.HandleFunc("/auth/session", handleSession)
	mux.HandleFunc("/auth/logout", requireStateProtection(handleLogout))
	mux.HandleFunc("/process/kill", requireStateProtection(killProcessHandler))

	addr := os.Getenv("SCUDOZI_ADDR")
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:8080"
	}
	log.Printf("Scudozi running on %s\n", addr)

	handler := securityHeaders(enforceLocalOnly(mux))
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Printf("Scudozi shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown failed: %w", err)
		}
		return nil
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	siteDir := os.Getenv("SCUDOZI_SITE_DIR")
	if strings.TrimSpace(siteDir) == "" {
		siteDir = "site"
	}
	if _, err := os.Stat(siteDir); err != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "ready",
		"site_dir": siteDir,
	})
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":    version,
		"commit":     commit,
		"build_date": buildDate,
		"uptime_sec": int(time.Since(startedAt).Seconds()),
	})
}
