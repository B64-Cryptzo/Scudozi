package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"scudozi/graph"
	"scudozi/scanner"
	"strconv"
	"strings"
)

type errorResponse struct {
	Error string `json:"error"`
}

func graphHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	services, err := scanner.ScanPorts()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
		return
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if err := killPID(req.PID); err != nil {
		logAudit("process.kill", sess.Username, sess.Role, "error", map[string]any{"pid": req.PID, "process": req.Process, "error": err.Error()})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logAudit("process.kill", sess.Username, sess.Role, "success", map[string]any{"pid": req.PID, "process": req.Process})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": fmt.Sprintf("Terminated %s (pid %d)", req.Process, req.PID),
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

func Run() error {
	if err := initAuth(); err != nil {
		return fmt.Errorf("auth init failed: %w", err)
	}

	siteDir := os.Getenv("SCUDOZI_SITE_DIR")
	if strings.TrimSpace(siteDir) == "" {
		siteDir = "site"
	}
	http.Handle("/", securityHeaders(http.FileServer(http.Dir(siteDir))))
	http.HandleFunc("/graph", securityHeaders(authRequired(graphHandler)).ServeHTTP)
	http.HandleFunc("/auth/srp/start", securityHeaders(http.HandlerFunc(handleSRPStart)).ServeHTTP)
	http.HandleFunc("/auth/srp/verify", securityHeaders(http.HandlerFunc(handleSRPVerify)).ServeHTTP)
	http.HandleFunc("/auth/session", securityHeaders(http.HandlerFunc(handleSession)).ServeHTTP)
	http.HandleFunc("/auth/logout", securityHeaders(requireStateProtection(handleLogout)).ServeHTTP)
	http.HandleFunc("/process/kill", securityHeaders(requireStateProtection(killProcessHandler)).ServeHTTP)

	addr := os.Getenv("SCUDOZI_ADDR")
	if strings.TrimSpace(addr) == "" {
		addr = ":8080"
	}
	log.Printf("Scudozi running on %s\n", addr)
	return http.ListenAndServe(addr, nil)
}
