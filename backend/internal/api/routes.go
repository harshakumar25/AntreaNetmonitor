package api

import (
	"encoding/json"
	"net/http"
	"time"

	"network-monitor/internal/capture"
	"network-monitor/pkg/models"

	"github.com/gorilla/mux"
)

// RegisterRoutes registers all API routes
func RegisterRoutes(router *mux.Router, captureEngine *capture.CaptureEngine) {
	handler := &APIHandler{capture: captureEngine}

	router.HandleFunc("/stats/live", handler.GetLiveStats).Methods("GET")
	router.HandleFunc("/stats/historical", handler.GetHistoricalStats).Methods("GET")
	router.HandleFunc("/connections", handler.GetConnections).Methods("GET")
	router.HandleFunc("/alerts", handler.GetAlerts).Methods("GET")
	router.HandleFunc("/topology", handler.GetTopology).Methods("GET")
	router.HandleFunc("/filters", handler.CreateFilter).Methods("POST")
	router.HandleFunc("/filters", handler.GetFilters).Methods("GET")

	// BPF Comparison Tool routes
	bpfHandler := NewBPFHandler()
	router.HandleFunc("/bpf/compare", bpfHandler.CompareBPF).Methods("POST")
	router.HandleFunc("/bpf/generate", bpfHandler.GenerateBPF).Methods("POST")
	router.HandleFunc("/bpf/validate", bpfHandler.ValidateFilter).Methods("POST")
	router.HandleFunc("/bpf/opcodes", bpfHandler.GetOpcodes).Methods("GET")
	router.HandleFunc("/bpf/export", bpfHandler.ExportBPF).Methods("POST")
	router.HandleFunc("/bpf/metrics", bpfHandler.GetBPFMetrics).Methods("POST")
	router.HandleFunc("/bpf/batch", bpfHandler.BatchCompare).Methods("POST")

	// Pcap file analysis routes
	router.HandleFunc("/bpf/pcap/analyze", bpfHandler.AnalyzePcap).Methods("POST")
	router.HandleFunc("/bpf/pcap/upload", bpfHandler.UploadPcap).Methods("POST")
	router.HandleFunc("/bpf/pcap/test", bpfHandler.TestFilterOnPcap).Methods("POST")

	// Antrea integration routes
	router.HandleFunc("/bpf/antrea/status", bpfHandler.GetAntreaStatus).Methods("GET")
	router.HandleFunc("/bpf/antrea/filters", bpfHandler.GetAntreaFilters).Methods("GET")
	router.HandleFunc("/bpf/antrea/compare-live", bpfHandler.CompareLiveCapture).Methods("POST")

	// Advanced analysis routes
	router.HandleFunc("/bpf/analyze", bpfHandler.FullAnalysis).Methods("POST")
	router.HandleFunc("/bpf/flow", bpfHandler.GetInstructionFlow).Methods("POST")
	router.HandleFunc("/bpf/optimize", bpfHandler.GetOptimizations).Methods("POST")
	router.HandleFunc("/bpf/k8s-presets", bpfHandler.GetK8sPresets).Methods("GET")
	router.HandleFunc("/bpf/report", bpfHandler.GenerateReport).Methods("POST")

	// Test generation routes (LFX Mentorship)
	router.HandleFunc("/bpf/testgen/generate", bpfHandler.GenerateTestCases).Methods("POST")
	router.HandleFunc("/bpf/testgen/suite", bpfHandler.GetTestSuite).Methods("GET")
	router.HandleFunc("/bpf/testgen/go-test", bpfHandler.GenerateGoTest).Methods("POST")
	router.HandleFunc("/bpf/testgen/run", bpfHandler.RunTestSuite).Methods("POST")
	router.HandleFunc("/bpf/testgen/categories", bpfHandler.GetTestCategories).Methods("GET")

	// Semantic Equivalence Analysis (LFX Requirement)
	router.HandleFunc("/bpf/semantic/analyze", bpfHandler.CheckSemanticEquivalence).Methods("POST")
}

// APIHandler handles API requests
type APIHandler struct {
	capture *capture.CaptureEngine
	filters []models.Filter
}

// GetLiveStats returns current traffic statistics
func (h *APIHandler) GetLiveStats(w http.ResponseWriter, r *http.Request) {
	stats := h.capture.GetCurrentStats()
	respondJSON(w, http.StatusOK, stats)
}

// GetHistoricalStats returns historical traffic data
func (h *APIHandler) GetHistoricalStats(w http.ResponseWriter, r *http.Request) {
	// Generate sample historical data
	data := make([]models.TrafficStats, 0, 60)
	now := time.Now()

	for i := 59; i >= 0; i-- {
		ts := now.Add(-time.Duration(i) * time.Minute)
		data = append(data, models.TrafficStats{
			Timestamp:         ts,
			TotalBytes:        int64(1000000 + i*10000),
			TotalPackets:      int64(10000 + i*100),
			BytesPerSecond:    float64(50000 + i*500),
			PacketsPerSecond:  float64(500 + i*5),
			ActiveConnections: 100 + i,
			BandwidthIn:       float64(25000 + i*300),
			BandwidthOut:      float64(25000 + i*200),
			LatencyAvg:        float64(30 + i%20),
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"data":       data,
		"startTime":  now.Add(-60 * time.Minute),
		"endTime":    now,
		"dataPoints": len(data),
	})
}

// GetConnections returns active connections
func (h *APIHandler) GetConnections(w http.ResponseWriter, r *http.Request) {
	connections := h.capture.GetConnections()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"connections": connections,
		"total":       len(connections),
	})
}

// GetAlerts returns recent alerts
func (h *APIHandler) GetAlerts(w http.ResponseWriter, r *http.Request) {
	// Return sample alerts
	alerts := []models.Alert{
		{
			ID:        "alert-1",
			Type:      "warning",
			Title:     "High Bandwidth Usage",
			Message:   "Bandwidth usage exceeded 80% threshold on interface eth0",
			Source:    "192.168.1.1",
			Timestamp: time.Now().Add(-5 * time.Minute),
			Resolved:  false,
		},
		{
			ID:        "alert-2",
			Type:      "info",
			Title:     "New Device Connected",
			Message:   "Device with MAC 00:1B:44:11:3A:B7 connected to network",
			Source:    "192.168.1.50",
			Timestamp: time.Now().Add(-15 * time.Minute),
			Resolved:  true,
		},
		{
			ID:        "alert-3",
			Type:      "critical",
			Title:     "Potential Security Threat",
			Message:   "Multiple failed authentication attempts detected from external IP",
			Source:    "203.0.113.50",
			Timestamp: time.Now().Add(-2 * time.Minute),
			Resolved:  false,
		},
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"alerts":     alerts,
		"total":      len(alerts),
		"unresolved": 2,
	})
}

// GetTopology returns network topology data
func (h *APIHandler) GetTopology(w http.ResponseWriter, r *http.Request) {
	topology := models.NetworkTopology{
		Nodes: []models.TopologyNode{
			{ID: "router-1", Label: "Main Router", Type: "router", IP: "192.168.1.1", Status: "active", Traffic: 1500000},
			{ID: "server-1", Label: "Web Server", Type: "server", IP: "192.168.1.10", Status: "active", Traffic: 800000},
			{ID: "server-2", Label: "DB Server", Type: "server", IP: "192.168.1.20", Status: "active", Traffic: 500000},
			{ID: "server-3", Label: "API Server", Type: "server", IP: "192.168.1.30", Status: "warning", Traffic: 1200000},
			{ID: "client-1", Label: "Workstation 1", Type: "client", IP: "192.168.1.100", Status: "active", Traffic: 100000},
			{ID: "client-2", Label: "Workstation 2", Type: "client", IP: "192.168.1.101", Status: "idle", Traffic: 50000},
			{ID: "external-1", Label: "CDN", Type: "external", IP: "142.250.190.46", Status: "active", Traffic: 2000000},
			{ID: "external-2", Label: "DNS", Type: "external", IP: "8.8.8.8", Status: "active", Traffic: 100000},
		},
		Edges: []models.TopologyEdge{
			{Source: "router-1", Target: "server-1", Weight: 800000, Protocol: "TCP", Bandwidth: 1000},
			{Source: "router-1", Target: "server-2", Weight: 500000, Protocol: "TCP", Bandwidth: 500},
			{Source: "router-1", Target: "server-3", Weight: 1200000, Protocol: "TCP", Bandwidth: 1200},
			{Source: "router-1", Target: "client-1", Weight: 100000, Protocol: "TCP", Bandwidth: 100},
			{Source: "router-1", Target: "client-2", Weight: 50000, Protocol: "TCP", Bandwidth: 50},
			{Source: "router-1", Target: "external-1", Weight: 2000000, Protocol: "HTTPS", Bandwidth: 2000},
			{Source: "router-1", Target: "external-2", Weight: 100000, Protocol: "DNS", Bandwidth: 100},
			{Source: "server-1", Target: "server-2", Weight: 300000, Protocol: "TCP", Bandwidth: 300},
			{Source: "server-3", Target: "server-2", Weight: 400000, Protocol: "TCP", Bandwidth: 400},
		},
	}

	respondJSON(w, http.StatusOK, topology)
}

// CreateFilter creates a new packet filter
func (h *APIHandler) CreateFilter(w http.ResponseWriter, r *http.Request) {
	var filter models.Filter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	filter.ID = "filter-" + time.Now().Format("20060102150405")
	filter.Active = true
	h.filters = append(h.filters, filter)

	respondJSON(w, http.StatusCreated, filter)
}

// GetFilters returns all filters
func (h *APIHandler) GetFilters(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"filters": h.filters,
		"total":   len(h.filters),
	})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
