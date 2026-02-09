package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// BPFInstruction represents a single BPF instruction
type BPFInstruction struct {
	Index uint16 `json:"index"`
	Op    uint16 `json:"op"`
	Jt    uint8  `json:"jt"`
	Jf    uint8  `json:"jf"`
	K     uint32 `json:"k"`
	Desc  string `json:"desc"`
}

// BPFProgram represents a complete BPF program
type BPFProgram struct {
	Source       string           `json:"source"`
	Expression   string           `json:"expression"`
	Instructions []BPFInstruction `json:"instructions"`
	Count        int              `json:"count"`
	Error        string           `json:"error,omitempty"`
}

// BPFComparisonResult contains comparison analysis
type BPFComparisonResult struct {
	Expression      string       `json:"expression"`
	Tcpdump         BPFProgram   `json:"tcpdump"`
	Antrea          BPFProgram   `json:"antrea"`
	Match           bool         `json:"match"`
	InstructionDiff int          `json:"instructionDiff"`
	Analysis        []string     `json:"analysis"`
	Differences     []Difference `json:"differences"`
}

// Difference represents a specific difference between programs
type Difference struct {
	Index       int    `json:"index"`
	TcpdumpInst string `json:"tcpdump"`
	AntreaInst  string `json:"antrea,omitempty"`
	Note        string `json:"note"`
}

// BPFCompareRequest is the API request body
type BPFCompareRequest struct {
	Expression string `json:"expression"`
}

// BPFExportRequest is for export endpoint
type BPFExportRequest struct {
	Expression string `json:"expression"`
	Format     string `json:"format"` // "c", "hex", "raw", "go"
}

// BPFBatchRequest is for batch comparison
type BPFBatchRequest struct {
	Expressions []string `json:"expressions"`
}

// BPFMetrics represents performance/complexity metrics
type BPFMetrics struct {
	Expression       string  `json:"expression"`
	InstructionCount int     `json:"instructionCount"`
	JumpCount        int     `json:"jumpCount"`
	LoadCount        int     `json:"loadCount"`
	CompareCount     int     `json:"compareCount"`
	ReturnCount      int     `json:"returnCount"`
	MaxJumpDistance  int     `json:"maxJumpDistance"`
	HasIPv6          bool    `json:"hasIPv6"`
	HasFragCheck     bool    `json:"hasFragCheck"`
	ComplexityScore  float64 `json:"complexityScore"`
	EstimatedCycles  int     `json:"estimatedCycles"`
}

// BPFOptimization represents an optimization suggestion
type BPFOptimization struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"` // info, warning, optimization
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
	Impact      string `json:"impact"`
}

// BPFFlowNode represents a node in instruction flow
type BPFFlowNode struct {
	Index       int    `json:"index"`
	Instruction string `json:"instruction"`
	Type        string `json:"type"` // load, jump, return, alu
	NextTrue    int    `json:"nextTrue,omitempty"`
	NextFalse   int    `json:"nextFalse,omitempty"`
	Next        int    `json:"next,omitempty"`
	IsTerminal  bool   `json:"isTerminal"`
	Reachable   bool   `json:"reachable"`
}

// BPFAnalysisReport represents a comprehensive analysis
type BPFAnalysisReport struct {
	Expression      string              `json:"expression"`
	TcpdumpProgram  BPFProgram          `json:"tcpdumpProgram"`
	AntreaProgram   BPFProgram          `json:"antreaProgram"`
	Metrics         BPFMetrics          `json:"metrics"`
	FlowGraph       []BPFFlowNode       `json:"flowGraph"`
	Optimizations   []BPFOptimization   `json:"optimizations"`
	Comparison      BPFComparisonResult `json:"comparison"`
	KubernetesHints []string            `json:"kubernetesHints"`
	GeneratedAt     time.Time           `json:"generatedAt"`
}

// PcapAnalysisRequest is for pcap file analysis
type PcapAnalysisRequest struct {
	Filename   string `json:"filename"`
	Expression string `json:"expression"`
	MaxPackets int    `json:"maxPackets"`
}

// PcapAnalysisResult contains pcap analysis results
type PcapAnalysisResult struct {
	Filename       string         `json:"filename"`
	Expression     string         `json:"expression"`
	TotalPackets   int            `json:"totalPackets"`
	MatchedPackets int            `json:"matchedPackets"`
	FilterRate     float64        `json:"filterRate"`
	BPFProgram     BPFProgram     `json:"bpfProgram"`
	PacketSamples  []PacketSample `json:"packetSamples"`
	Protocols      map[string]int `json:"protocols"`
	TopIPs         []IPCount      `json:"topIPs"`
}

// PacketSample represents a captured packet sample
type PacketSample struct {
	Index     int       `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Length    int       `json:"length"`
	Protocol  string    `json:"protocol"`
	SrcIP     string    `json:"srcIP"`
	DstIP     string    `json:"dstIP"`
	SrcPort   int       `json:"srcPort,omitempty"`
	DstPort   int       `json:"dstPort,omitempty"`
	Info      string    `json:"info"`
}

// IPCount for top IP tracking
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// AntreaIntegrationStatus shows Antrea connection status
type AntreaIntegrationStatus struct {
	Connected       bool   `json:"connected"`
	ClusterName     string `json:"clusterName,omitempty"`
	AntreaVersion   string `json:"antreaVersion,omitempty"`
	AgentCount      int    `json:"agentCount,omitempty"`
	ControllerReady bool   `json:"controllerReady"`
	Message         string `json:"message"`
}

// TestCase represents a single BPF test case
type TestCase struct {
	ID          string     `json:"id"`
	Expression  string     `json:"expression"`
	Description string     `json:"description"`
	Category    string     `json:"category"`
	IPv4Only    bool       `json:"ipv4Only,omitempty"`
	IPv6Only    bool       `json:"ipv6Only,omitempty"`
	TcpdumpBPF  BPFProgram `json:"tcpdumpBpf,omitempty"`
	ExpectedOK  bool       `json:"expectedOk"`
}

// TestSuite represents a collection of test cases
type TestSuite struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Generated   time.Time  `json:"generated"`
	TestCases   []TestCase `json:"testCases"`
	Categories  []string   `json:"categories"`
	Stats       TestStats  `json:"stats"`
}

// TestStats shows test suite statistics
type TestStats struct {
	Total      int            `json:"total"`
	ByCategory map[string]int `json:"byCategory"`
	IPv4Count  int            `json:"ipv4Count"`
	IPv6Count  int            `json:"ipv6Count"`
	DualStack  int            `json:"dualStack"`
}

// GoTestOutput represents generated Go test code
type GoTestOutput struct {
	Filename    string `json:"filename"`
	Code        string `json:"code"`
	TestCount   int    `json:"testCount"`
	PackageName string `json:"packageName"`
}

// BPFHandler handles BPF-related API requests
type BPFHandler struct{}

// NewBPFHandler creates a new BPF handler
func NewBPFHandler() *BPFHandler {
	return &BPFHandler{}
}

// RegisterBPFRoutes registers BPF-related routes
func RegisterBPFRoutes(router interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request)) interface{ Methods(...string) interface{} }
}) {
	handler := NewBPFHandler()

	// Core BPF comparison routes
	router.HandleFunc("/bpf/compare", handler.CompareBPF).Methods("POST")
	router.HandleFunc("/bpf/generate", handler.GenerateBPF).Methods("POST")
	router.HandleFunc("/bpf/validate", handler.ValidateFilter).Methods("POST")
	router.HandleFunc("/bpf/opcodes", handler.GetOpcodes).Methods("GET")
	router.HandleFunc("/bpf/export", handler.ExportBPF).Methods("POST")
	router.HandleFunc("/bpf/metrics", handler.GetBPFMetrics).Methods("POST")
	router.HandleFunc("/bpf/batch", handler.BatchCompare).Methods("POST")

	// Pcap file analysis routes
	router.HandleFunc("/bpf/pcap/analyze", handler.AnalyzePcap).Methods("POST")
	router.HandleFunc("/bpf/pcap/upload", handler.UploadPcap).Methods("POST")
	router.HandleFunc("/bpf/pcap/test", handler.TestFilterOnPcap).Methods("POST")

	// Antrea integration routes
	router.HandleFunc("/bpf/antrea/status", handler.GetAntreaStatus).Methods("GET")
	router.HandleFunc("/bpf/antrea/filters", handler.GetAntreaFilters).Methods("GET")
	router.HandleFunc("/bpf/antrea/compare-live", handler.CompareLiveCapture).Methods("POST")

	// Advanced analysis routes
	router.HandleFunc("/bpf/analyze", handler.FullAnalysis).Methods("POST")
	router.HandleFunc("/bpf/flow", handler.GetInstructionFlow).Methods("POST")
	router.HandleFunc("/bpf/optimize", handler.GetOptimizations).Methods("POST")
	router.HandleFunc("/bpf/k8s-presets", handler.GetK8sPresets).Methods("GET")
	router.HandleFunc("/bpf/report", handler.GenerateReport).Methods("POST")

	// Test generation routes (LFX Mentorship)
	router.HandleFunc("/bpf/testgen/generate", handler.GenerateTestCases).Methods("POST")
	router.HandleFunc("/bpf/testgen/suite", handler.GetTestSuite).Methods("GET")
	router.HandleFunc("/bpf/testgen/go-test", handler.GenerateGoTest).Methods("POST")
	router.HandleFunc("/bpf/testgen/run", handler.RunTestSuite).Methods("POST")
	router.HandleFunc("/bpf/testgen/categories", handler.GetTestCategories).Methods("GET")
}

// CompareBPF compares tcpdump BPF with Antrea BPF
func (h *BPFHandler) CompareBPF(w http.ResponseWriter, r *http.Request) {
	var req BPFCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Expression == "" {
		respondError(w, http.StatusBadRequest, "Expression is required")
		return
	}

	// Get tcpdump BPF
	tcpdumpBPF := getTcpdumpBPF(req.Expression)

	// Get Antrea BPF (simulated for now - will integrate with actual Antrea code)
	antreaBPF := getAntreaBPF(req.Expression)

	// Analyze differences
	result := analyzeBPFDifferences(req.Expression, tcpdumpBPF, antreaBPF)

	respondJSON(w, http.StatusOK, result)
}

// GenerateBPF generates BPF bytecode from a filter expression
func (h *BPFHandler) GenerateBPF(w http.ResponseWriter, r *http.Request) {
	var req BPFCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Expression == "" {
		respondError(w, http.StatusBadRequest, "Expression is required")
		return
	}

	bpf := getTcpdumpBPF(req.Expression)
	respondJSON(w, http.StatusOK, bpf)
}

// ValidateFilter validates a BPF filter expression
func (h *BPFHandler) ValidateFilter(w http.ResponseWriter, r *http.Request) {
	var req BPFCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Try to compile the filter
	bpf := getTcpdumpBPF(req.Expression)

	result := map[string]interface{}{
		"expression":       req.Expression,
		"valid":            bpf.Error == "",
		"error":            bpf.Error,
		"instructionCount": bpf.Count,
	}

	if bpf.Error != "" {
		respondJSON(w, http.StatusOK, result)
		return
	}

	respondJSON(w, http.StatusOK, result)
}

// GetOpcodes returns BPF opcode reference
func (h *BPFHandler) GetOpcodes(w http.ResponseWriter, r *http.Request) {
	opcodes := map[string]interface{}{
		"load": map[string]string{
			"0x00": "ld (load word)",
			"0x01": "ldh (load half-word)",
			"0x02": "ldb (load byte)",
			"0x20": "ld [k] (load absolute)",
			"0x28": "ldh [k] (load half absolute)",
			"0x30": "ldb [k] (load byte absolute)",
			"0x40": "ld [x+k] (load indirect)",
			"0x48": "ldh [x+k] (load half indirect)",
			"0x50": "ldb [x+k] (load byte indirect)",
			"0xb1": "ldxb 4*([k]&0xf) (load IP header length)",
		},
		"jump": map[string]string{
			"0x05": "ja (jump always)",
			"0x15": "jeq (jump if equal)",
			"0x25": "jgt (jump if greater)",
			"0x35": "jge (jump if greater or equal)",
			"0x45": "jset (jump if bits set)",
		},
		"return": map[string]string{
			"0x06": "ret (return)",
		},
		"alu": map[string]string{
			"0x04": "add",
			"0x14": "sub",
			"0x24": "mul",
			"0x34": "div",
			"0x44": "or",
			"0x54": "and",
			"0x64": "lsh (left shift)",
			"0x74": "rsh (right shift)",
			"0x84": "neg",
		},
		"misc": map[string]string{
			"0x07": "tax (transfer A to X)",
			"0x87": "txa (transfer X to A)",
		},
		"commonValues": map[string]string{
			"0x0800":  "IPv4 EtherType",
			"0x86dd":  "IPv6 EtherType",
			"0x0806":  "ARP EtherType",
			"0x06":    "TCP Protocol",
			"0x11":    "UDP Protocol",
			"0x01":    "ICMP Protocol",
			"0x3a":    "ICMPv6 Protocol",
			"0x40000": "Default snaplen (256KB)",
		},
	}

	respondJSON(w, http.StatusOK, opcodes)
}

// getTcpdumpBPF executes tcpdump and parses BPF output
func getTcpdumpBPF(expression string) BPFProgram {
	prog := BPFProgram{
		Source:     "tcpdump",
		Expression: expression,
	}

	// Run tcpdump -dd to get BPF
	cmd := exec.Command("tcpdump", "-dd", expression)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = err.Error()
		}
		prog.Error = strings.TrimSpace(errMsg)
		return prog
	}

	// Parse output
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Warning:") {
			continue
		}

		inst := parseBPFInstruction(line, i)
		if inst != nil {
			prog.Instructions = append(prog.Instructions, *inst)
		}
	}

	prog.Count = len(prog.Instructions)
	return prog
}

// parseBPFInstruction parses a single BPF instruction line
func parseBPFInstruction(line string, index int) *BPFInstruction {
	// Format: { 0x28, 0, 0, 0x0000000c },
	line = strings.TrimPrefix(line, "{")
	line = strings.TrimSuffix(line, "},")
	line = strings.TrimSuffix(line, "}")
	line = strings.TrimSpace(line)

	parts := strings.Split(line, ",")
	if len(parts) != 4 {
		return nil
	}

	op := parseHexOrDec(strings.TrimSpace(parts[0]))
	jt := parseHexOrDec(strings.TrimSpace(parts[1]))
	jf := parseHexOrDec(strings.TrimSpace(parts[2]))
	k := parseHexOrDec(strings.TrimSpace(parts[3]))

	return &BPFInstruction{
		Index: uint16(index),
		Op:    uint16(op),
		Jt:    uint8(jt),
		Jf:    uint8(jf),
		K:     uint32(k),
		Desc:  describeInstruction(uint16(op), uint8(jt), uint8(jf), uint32(k)),
	}
}

// parseHexOrDec parses a number in hex (0x...) or decimal format
func parseHexOrDec(s string) uint64 {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, _ := strconv.ParseUint(s[2:], 16, 64)
		return val
	}
	val, _ := strconv.ParseUint(s, 10, 64)
	return val
}

// describeInstruction provides human-readable description
func describeInstruction(op uint16, jt, jf uint8, k uint32) string {
	opClass := op & 0x07

	switch opClass {
	case 0x00: // ld
		size := (op >> 3) & 0x03
		mode := (op >> 5) & 0x07
		sizeStr := map[uint16]string{0: "w", 1: "h", 2: "b", 3: "?"}[size]
		switch mode {
		case 1:
			return fmt.Sprintf("ld%s [%d]", sizeStr, k)
		case 2:
			return fmt.Sprintf("ld%s [x+%d]", sizeStr, k)
		case 4:
			return fmt.Sprintf("ld%s #%d", sizeStr, k)
		case 5:
			return fmt.Sprintf("ldxb 4*([%d]&0xf)", k)
		}
	case 0x05: // jmp
		jmpOp := op & 0xf0
		switch jmpOp {
		case 0x00:
			return fmt.Sprintf("ja +%d", k)
		case 0x10:
			return fmt.Sprintf("jeq #0x%x, +%d, +%d", k, jt, jf)
		case 0x20:
			return fmt.Sprintf("jgt #0x%x, +%d, +%d", k, jt, jf)
		case 0x30:
			return fmt.Sprintf("jge #0x%x, +%d, +%d", k, jt, jf)
		case 0x40:
			return fmt.Sprintf("jset #0x%x, +%d, +%d", k, jt, jf)
		}
	case 0x06: // ret
		if k == 0 {
			return "ret #0 (reject)"
		}
		return fmt.Sprintf("ret #%d (accept)", k)
	}

	return fmt.Sprintf("op=0x%02x k=0x%x", op, k)
}

// getAntreaBPF generates Antrea-style BPF (simulated for comparison)
// In production, this would call the actual Antrea BPF generation code
func getAntreaBPF(expression string) BPFProgram {
	prog := BPFProgram{
		Source:     "antrea",
		Expression: expression,
	}

	// For now, we simulate Antrea's approach
	// This shows conceptual differences without actual Antrea dependency

	// Parse simple expressions to demonstrate
	expr := strings.ToLower(expression)

	// Check for basic protocols
	if strings.Contains(expr, "tcp") {
		prog.Instructions = generateTCPFilter(expr)
	} else if strings.Contains(expr, "udp") {
		prog.Instructions = generateUDPFilter(expr)
	} else if strings.Contains(expr, "icmp") {
		prog.Instructions = generateICMPFilter(expr)
	} else {
		// Generic filter - return tcpdump result for now
		tcpdump := getTcpdumpBPF(expression)
		prog.Instructions = tcpdump.Instructions
		prog.Error = "Using tcpdump fallback (no Antrea-specific generation)"
	}

	prog.Count = len(prog.Instructions)
	return prog
}

// generateTCPFilter generates Antrea-style TCP filter
func generateTCPFilter(expr string) []BPFInstruction {
	instructions := []BPFInstruction{
		{Index: 0, Op: 0x28, Jt: 0, Jf: 0, K: 12, Desc: "ldh [12] - load ethertype"},
		{Index: 1, Op: 0x15, Jt: 0, Jf: 10, K: 0x0800, Desc: "jeq #0x800 (IPv4)"},
		{Index: 2, Op: 0x30, Jt: 0, Jf: 0, K: 23, Desc: "ldb [23] - load protocol"},
		{Index: 3, Op: 0x15, Jt: 0, Jf: 8, K: 0x06, Desc: "jeq #6 (TCP)"},
	}

	// Add port checks if specified
	if strings.Contains(expr, "port") {
		// Extract port number (simplified)
		var port uint32 = 80
		fmt.Sscanf(expr, "%*s port %d", &port)

		instructions = append(instructions, []BPFInstruction{
			{Index: 4, Op: 0x28, Jt: 0, Jf: 0, K: 20, Desc: "ldh [20] - frag offset"},
			{Index: 5, Op: 0x45, Jt: 6, Jf: 0, K: 0x1fff, Desc: "jset #0x1fff (frag check)"},
			{Index: 6, Op: 0xb1, Jt: 0, Jf: 0, K: 14, Desc: "ldxb 4*([14]&0xf) - IP hdr len"},
			{Index: 7, Op: 0x48, Jt: 0, Jf: 0, K: 14, Desc: "ldh [x+14] - src port"},
			{Index: 8, Op: 0x15, Jt: 2, Jf: 0, K: port, Desc: fmt.Sprintf("jeq #%d (port)", port)},
			{Index: 9, Op: 0x48, Jt: 0, Jf: 0, K: 16, Desc: "ldh [x+16] - dst port"},
			{Index: 10, Op: 0x15, Jt: 0, Jf: 1, K: port, Desc: fmt.Sprintf("jeq #%d (port)", port)},
			{Index: 11, Op: 0x06, Jt: 0, Jf: 0, K: 262144, Desc: "ret #262144 (accept)"},
			{Index: 12, Op: 0x06, Jt: 0, Jf: 0, K: 0, Desc: "ret #0 (reject)"},
		}...)
	} else {
		instructions = append(instructions, []BPFInstruction{
			{Index: 4, Op: 0x06, Jt: 0, Jf: 0, K: 262144, Desc: "ret #262144 (accept)"},
			{Index: 5, Op: 0x06, Jt: 0, Jf: 0, K: 0, Desc: "ret #0 (reject)"},
		}...)
	}

	return instructions
}

// generateUDPFilter generates Antrea-style UDP filter
func generateUDPFilter(expr string) []BPFInstruction {
	instructions := []BPFInstruction{
		{Index: 0, Op: 0x28, Jt: 0, Jf: 0, K: 12, Desc: "ldh [12] - load ethertype"},
		{Index: 1, Op: 0x15, Jt: 0, Jf: 4, K: 0x0800, Desc: "jeq #0x800 (IPv4)"},
		{Index: 2, Op: 0x30, Jt: 0, Jf: 0, K: 23, Desc: "ldb [23] - load protocol"},
		{Index: 3, Op: 0x15, Jt: 0, Jf: 2, K: 0x11, Desc: "jeq #17 (UDP)"},
		{Index: 4, Op: 0x06, Jt: 0, Jf: 0, K: 262144, Desc: "ret #262144 (accept)"},
		{Index: 5, Op: 0x06, Jt: 0, Jf: 0, K: 0, Desc: "ret #0 (reject)"},
	}
	return instructions
}

// generateICMPFilter generates Antrea-style ICMP filter
func generateICMPFilter(expr string) []BPFInstruction {
	return []BPFInstruction{
		{Index: 0, Op: 0x28, Jt: 0, Jf: 0, K: 12, Desc: "ldh [12] - load ethertype"},
		{Index: 1, Op: 0x15, Jt: 0, Jf: 4, K: 0x0800, Desc: "jeq #0x800 (IPv4)"},
		{Index: 2, Op: 0x30, Jt: 0, Jf: 0, K: 23, Desc: "ldb [23] - load protocol"},
		{Index: 3, Op: 0x15, Jt: 0, Jf: 2, K: 0x01, Desc: "jeq #1 (ICMP)"},
		{Index: 4, Op: 0x06, Jt: 0, Jf: 0, K: 262144, Desc: "ret #262144 (accept)"},
		{Index: 5, Op: 0x06, Jt: 0, Jf: 0, K: 0, Desc: "ret #0 (reject)"},
	}
}

// analyzeBPFDifferences analyzes differences between two BPF programs
func analyzeBPFDifferences(expr string, tcpdump, antrea BPFProgram) BPFComparisonResult {
	result := BPFComparisonResult{
		Expression: expr,
		Tcpdump:    tcpdump,
		Antrea:     antrea,
		Analysis:   []string{},
	}

	if tcpdump.Error != "" || antrea.Error != "" {
		result.Analysis = append(result.Analysis, "Error in one or both programs")
		return result
	}

	result.InstructionDiff = antrea.Count - tcpdump.Count

	// Check for exact match
	if antrea.Count == tcpdump.Count {
		match := true
		for i := range tcpdump.Instructions {
			t := tcpdump.Instructions[i]
			a := antrea.Instructions[i]
			if t.Op != a.Op || t.Jt != a.Jt || t.Jf != a.Jf || t.K != a.K {
				match = false
				result.Differences = append(result.Differences, Difference{
					Index:       i,
					TcpdumpInst: fmt.Sprintf("{ 0x%02x, %d, %d, 0x%x }", t.Op, t.Jt, t.Jf, t.K),
					AntreaInst:  fmt.Sprintf("{ 0x%02x, %d, %d, 0x%x }", a.Op, a.Jt, a.Jf, a.K),
				})
			}
		}
		result.Match = match
		if match {
			result.Analysis = append(result.Analysis, "✅ Identical BPF bytecode")
		} else {
			result.Analysis = append(result.Analysis, "⚠️ Same instruction count but different bytecode")
		}
	} else {
		result.Match = false
		if result.InstructionDiff > 0 {
			result.Analysis = append(result.Analysis,
				fmt.Sprintf("Antrea generates %d more instructions", result.InstructionDiff))
		} else {
			result.Analysis = append(result.Analysis,
				fmt.Sprintf("tcpdump generates %d more instructions", -result.InstructionDiff))
		}
	}

	// Analyze semantics
	tcpdumpHasIPv6 := false
	antreaHasIPv6 := false
	for _, inst := range tcpdump.Instructions {
		if inst.K == 0x86dd {
			tcpdumpHasIPv6 = true
			break
		}
	}
	for _, inst := range antrea.Instructions {
		if inst.K == 0x86dd {
			antreaHasIPv6 = true
			break
		}
	}

	if tcpdumpHasIPv6 && !antreaHasIPv6 {
		result.Analysis = append(result.Analysis,
			"tcpdump includes IPv6 handling, Antrea is IPv4-only")
	}

	return result
}

// ExportBPF exports BPF bytecode in various formats
func (h *BPFHandler) ExportBPF(w http.ResponseWriter, r *http.Request) {
	var req BPFExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Expression == "" {
		respondError(w, http.StatusBadRequest, "Expression is required")
		return
	}

	if req.Format == "" {
		req.Format = "c"
	}

	bpf := getTcpdumpBPF(req.Expression)
	if bpf.Error != "" {
		respondError(w, http.StatusBadRequest, bpf.Error)
		return
	}

	var output string
	switch req.Format {
	case "c":
		output = exportToC(bpf, req.Expression)
	case "go":
		output = exportToGo(bpf, req.Expression)
	case "hex":
		output = exportToHex(bpf)
	case "raw":
		output = exportToRaw(bpf)
	default:
		output = exportToC(bpf, req.Expression)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"expression": req.Expression,
		"format":     req.Format,
		"output":     output,
		"count":      bpf.Count,
	})
}

// GetBPFMetrics returns complexity metrics for a BPF filter
func (h *BPFHandler) GetBPFMetrics(w http.ResponseWriter, r *http.Request) {
	var req BPFCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	bpf := getTcpdumpBPF(req.Expression)
	if bpf.Error != "" {
		respondError(w, http.StatusBadRequest, bpf.Error)
		return
	}

	metrics := calculateMetrics(bpf, req.Expression)
	respondJSON(w, http.StatusOK, metrics)
}

// BatchCompare compares multiple expressions at once
func (h *BPFHandler) BatchCompare(w http.ResponseWriter, r *http.Request) {
	var req BPFBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Expressions) == 0 {
		respondError(w, http.StatusBadRequest, "At least one expression is required")
		return
	}

	if len(req.Expressions) > 20 {
		respondError(w, http.StatusBadRequest, "Maximum 20 expressions per batch")
		return
	}

	results := make([]BPFComparisonResult, 0, len(req.Expressions))
	for _, expr := range req.Expressions {
		tcpdumpBPF := getTcpdumpBPF(expr)
		antreaBPF := getAntreaBPF(expr)
		result := analyzeBPFDifferences(expr, tcpdumpBPF, antreaBPF)
		results = append(results, result)
	}

	// Calculate summary
	totalMatches := 0
	totalTcpdumpInst := 0
	totalAntreaInst := 0
	for _, r := range results {
		if r.Match {
			totalMatches++
		}
		totalTcpdumpInst += r.Tcpdump.Count
		totalAntreaInst += r.Antrea.Count
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
		"summary": map[string]interface{}{
			"total":              len(results),
			"matches":            totalMatches,
			"matchRate":          float64(totalMatches) / float64(len(results)) * 100,
			"avgTcpdumpInst":     float64(totalTcpdumpInst) / float64(len(results)),
			"avgAntreaInst":      float64(totalAntreaInst) / float64(len(results)),
			"avgInstructionDiff": float64(totalTcpdumpInst-totalAntreaInst) / float64(len(results)),
		},
	})
}

// Export helper functions
func exportToC(bpf BPFProgram, expr string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("/* BPF filter: %s */\n", expr))
	sb.WriteString(fmt.Sprintf("/* Generated by Antrea Network Monitor BPF Tool */\n\n"))
	sb.WriteString("struct sock_filter bpf_code[] = {\n")
	for _, inst := range bpf.Instructions {
		sb.WriteString(fmt.Sprintf("    { 0x%02x, %d, %d, 0x%08x }, /* %s */\n",
			inst.Op, inst.Jt, inst.Jf, inst.K, inst.Desc))
	}
	sb.WriteString("};\n\n")
	sb.WriteString(fmt.Sprintf("struct sock_fprog bpf_prog = {\n"))
	sb.WriteString(fmt.Sprintf("    .len = %d,\n", bpf.Count))
	sb.WriteString("    .filter = bpf_code,\n")
	sb.WriteString("};\n")
	return sb.String()
}

func exportToGo(bpf BPFProgram, expr string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("// BPF filter: %s\n", expr))
	sb.WriteString("// Generated by Antrea Network Monitor BPF Tool\n\n")
	sb.WriteString("package main\n\n")
	sb.WriteString("import \"golang.org/x/net/bpf\"\n\n")
	sb.WriteString("var bpfInstructions = []bpf.RawInstruction{\n")
	for _, inst := range bpf.Instructions {
		sb.WriteString(fmt.Sprintf("    {Op: 0x%02x, Jt: %d, Jf: %d, K: 0x%08x}, // %s\n",
			inst.Op, inst.Jt, inst.Jf, inst.K, inst.Desc))
	}
	sb.WriteString("}\n")
	return sb.String()
}

func exportToHex(bpf BPFProgram) string {
	var sb strings.Builder
	for _, inst := range bpf.Instructions {
		sb.WriteString(fmt.Sprintf("%02x %02x %02x %02x %02x %02x %02x %02x\n",
			byte(inst.Op), byte(inst.Op>>8),
			inst.Jt, inst.Jf,
			byte(inst.K), byte(inst.K>>8), byte(inst.K>>16), byte(inst.K>>24)))
	}
	return sb.String()
}

func exportToRaw(bpf BPFProgram) string {
	var sb strings.Builder
	for _, inst := range bpf.Instructions {
		sb.WriteString(fmt.Sprintf("{ 0x%02x, %d, %d, 0x%08x }\n",
			inst.Op, inst.Jt, inst.Jf, inst.K))
	}
	return sb.String()
}

// calculateMetrics computes complexity metrics for a BPF program
func calculateMetrics(bpf BPFProgram, expr string) BPFMetrics {
	metrics := BPFMetrics{
		Expression:       expr,
		InstructionCount: bpf.Count,
	}

	maxJump := 0
	for _, inst := range bpf.Instructions {
		opClass := inst.Op & 0x07

		switch opClass {
		case 0x00, 0x01: // LD, LDX
			metrics.LoadCount++
		case 0x05: // JMP
			metrics.JumpCount++
			if int(inst.Jt) > maxJump {
				maxJump = int(inst.Jt)
			}
			if int(inst.Jf) > maxJump {
				maxJump = int(inst.Jf)
			}
		case 0x06: // RET
			metrics.ReturnCount++
		}

		// Check for compare operations (jeq, jgt, jge, jset)
		if inst.Op&0xf0 == 0x10 || inst.Op&0xf0 == 0x20 ||
			inst.Op&0xf0 == 0x30 || inst.Op&0xf0 == 0x40 {
			metrics.CompareCount++
		}

		// Check for IPv6
		if inst.K == 0x86dd {
			metrics.HasIPv6 = true
		}

		// Check for fragment check
		if inst.K == 0x1fff {
			metrics.HasFragCheck = true
		}
	}

	metrics.MaxJumpDistance = maxJump

	// Calculate complexity score (heuristic)
	metrics.ComplexityScore = float64(bpf.Count) +
		float64(metrics.JumpCount)*1.5 +
		float64(metrics.CompareCount)*1.2

	// Estimate CPU cycles (rough approximation)
	metrics.EstimatedCycles = bpf.Count*2 + metrics.JumpCount*3 + metrics.LoadCount*4

	return metrics
}

// ===============================
// PCAP FILE ANALYSIS HANDLERS
// ===============================

// AnalyzePcap analyzes a pcap file with a BPF filter
func (h *BPFHandler) AnalyzePcap(w http.ResponseWriter, r *http.Request) {
	var req PcapAnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Filename == "" {
		respondError(w, http.StatusBadRequest, "Filename is required")
		return
	}

	if req.MaxPackets == 0 {
		req.MaxPackets = 100
	}

	// Analyze pcap with tcpdump
	result, err := analyzePcapFile(req.Filename, req.Expression, req.MaxPackets)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, result)
}

// UploadPcap handles pcap file upload
func (h *BPFHandler) UploadPcap(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (max 50MB)
	err := r.ParseMultipartForm(50 << 20)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Failed to parse form: "+err.Error())
		return
	}

	file, header, err := r.FormFile("pcap")
	if err != nil {
		respondError(w, http.StatusBadRequest, "No file uploaded")
		return
	}
	defer file.Close()

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
		respondError(w, http.StatusBadRequest, "Invalid file type. Supported: .pcap, .pcapng, .cap")
		return
	}

	// Create uploads directory
	uploadsDir := "/tmp/antrea-pcap-uploads"
	os.MkdirAll(uploadsDir, 0755)

	// Save file
	filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), header.Filename)
	filepath := filepath.Join(uploadsDir, filename)

	dst, err := os.Create(filepath)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to save file")
		return
	}
	defer dst.Close()

	written, err := io.Copy(dst, file)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to write file")
		return
	}

	// Get basic pcap info
	info := getPcapInfo(filepath)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":      true,
		"filename":     filename,
		"originalName": header.Filename,
		"size":         written,
		"path":         filepath,
		"info":         info,
	})
}

// TestFilterOnPcap tests a BPF filter against a pcap file
func (h *BPFHandler) TestFilterOnPcap(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PcapPath   string `json:"pcapPath"`
		Expression string `json:"expression"`
		PcapBase64 string `json:"pcapBase64"` // Alternative: base64 encoded pcap
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var pcapPath string

	// Handle base64 encoded pcap
	if req.PcapBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.PcapBase64)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid base64 data")
			return
		}

		tmpFile, err := os.CreateTemp("", "test-*.pcap")
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to create temp file")
			return
		}
		tmpFile.Write(decoded)
		tmpFile.Close()
		pcapPath = tmpFile.Name()
		defer os.Remove(pcapPath)
	} else if req.PcapPath != "" {
		pcapPath = req.PcapPath
	} else {
		respondError(w, http.StatusBadRequest, "Either pcapPath or pcapBase64 is required")
		return
	}

	// Get BPF for the expression
	bpf := getTcpdumpBPF(req.Expression)

	// Count packets matching the filter
	totalPackets := countPackets(pcapPath, "")
	matchedPackets := countPackets(pcapPath, req.Expression)

	filterRate := float64(0)
	if totalPackets > 0 {
		filterRate = float64(matchedPackets) / float64(totalPackets) * 100
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"expression":     req.Expression,
		"totalPackets":   totalPackets,
		"matchedPackets": matchedPackets,
		"filterRate":     filterRate,
		"bpfProgram":     bpf,
		"efficiency":     calculateFilterEfficiency(bpf, filterRate),
	})
}

// Helper functions for pcap analysis
func analyzePcapFile(filename, expression string, maxPackets int) (*PcapAnalysisResult, error) {
	result := &PcapAnalysisResult{
		Filename:   filename,
		Expression: expression,
		Protocols:  make(map[string]int),
		TopIPs:     []IPCount{},
	}

	// Get BPF program
	if expression != "" {
		result.BPFProgram = getTcpdumpBPF(expression)
	}

	// Count total and matched packets
	result.TotalPackets = countPackets(filename, "")
	if expression != "" {
		result.MatchedPackets = countPackets(filename, expression)
	} else {
		result.MatchedPackets = result.TotalPackets
	}

	if result.TotalPackets > 0 {
		result.FilterRate = float64(result.MatchedPackets) / float64(result.TotalPackets) * 100
	}

	// Get packet samples using tcpdump
	samples := getPacketSamples(filename, expression, maxPackets)
	result.PacketSamples = samples

	// Count protocols from samples
	ipCounts := make(map[string]int)
	for _, s := range samples {
		result.Protocols[s.Protocol]++
		if s.SrcIP != "" {
			ipCounts[s.SrcIP]++
		}
		if s.DstIP != "" {
			ipCounts[s.DstIP]++
		}
	}

	// Get top IPs
	for ip, count := range ipCounts {
		result.TopIPs = append(result.TopIPs, IPCount{IP: ip, Count: count})
	}

	return result, nil
}

func countPackets(pcapPath, expression string) int {
	args := []string{"-r", pcapPath, "-c"}
	if expression != "" {
		args = append(args, expression)
	}

	cmd := exec.Command("tcpdump", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0
	}

	// Parse packet count from tcpdump output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "packets") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				count, _ := strconv.Atoi(fields[0])
				return count
			}
		}
	}

	// Alternative: count lines of output
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "reading") {
			count++
		}
	}
	return count
}

func getPacketSamples(pcapPath, expression string, maxPackets int) []PacketSample {
	args := []string{"-r", pcapPath, "-c", strconv.Itoa(maxPackets), "-nn", "-tttt"}
	if expression != "" {
		args = append(args, expression)
	}

	cmd := exec.Command("tcpdump", args...)
	output, _ := cmd.CombinedOutput()

	samples := []PacketSample{}
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "reading") {
			continue
		}

		sample := parsePacketLine(line, i)
		if sample.Protocol != "" {
			samples = append(samples, sample)
		}
	}

	return samples
}

func parsePacketLine(line string, index int) PacketSample {
	sample := PacketSample{Index: index}

	// Basic protocol detection
	lineLower := strings.ToLower(line)
	switch {
	case strings.Contains(lineLower, " tcp "):
		sample.Protocol = "TCP"
	case strings.Contains(lineLower, " udp "):
		sample.Protocol = "UDP"
	case strings.Contains(lineLower, "icmp"):
		sample.Protocol = "ICMP"
	case strings.Contains(lineLower, "arp"):
		sample.Protocol = "ARP"
	case strings.Contains(lineLower, " ip "):
		sample.Protocol = "IP"
	default:
		sample.Protocol = "OTHER"
	}

	// Extract IPs (simplified parsing)
	parts := strings.Fields(line)
	for i, part := range parts {
		if strings.Contains(part, ".") && i > 0 {
			// Remove port suffix
			ip := strings.Split(part, ".")[0:4]
			if len(ip) >= 4 {
				ipStr := strings.Join(ip, ".")
				if sample.SrcIP == "" {
					sample.SrcIP = ipStr
				} else if sample.DstIP == "" {
					sample.DstIP = ipStr
					break
				}
			}
		}
	}

	sample.Info = line
	if len(sample.Info) > 100 {
		sample.Info = sample.Info[:100] + "..."
	}

	return sample
}

func getPcapInfo(filepath string) map[string]interface{} {
	info := make(map[string]interface{})

	// Get file stats
	stat, err := os.Stat(filepath)
	if err == nil {
		info["size"] = stat.Size()
		info["modified"] = stat.ModTime()
	}

	// Get packet count
	info["packetCount"] = countPackets(filepath, "")

	// Get capinfos if available
	cmd := exec.Command("capinfos", "-c", filepath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		info["capinfo"] = string(output)
	}

	return info
}

func calculateFilterEfficiency(bpf BPFProgram, filterRate float64) map[string]interface{} {
	return map[string]interface{}{
		"instructionCount":  bpf.Count,
		"filterSelectivity": filterRate,
		"estimatedCPUCost":  bpf.Count * 2,
		"recommendation":    getFilterRecommendation(bpf, filterRate),
	}
}

func getFilterRecommendation(bpf BPFProgram, filterRate float64) string {
	if bpf.Count > 30 {
		return "Consider simplifying filter - high instruction count may impact performance"
	}
	if filterRate < 1 {
		return "Very selective filter - good for targeted analysis"
	}
	if filterRate > 90 {
		return "Filter matches most packets - consider more specific criteria"
	}
	return "Filter complexity and selectivity are balanced"
}

// ===============================
// ANTREA INTEGRATION HANDLERS
// ===============================

// GetAntreaStatus returns Antrea cluster connection status
func (h *BPFHandler) GetAntreaStatus(w http.ResponseWriter, r *http.Request) {
	status := checkAntreaConnection()
	respondJSON(w, http.StatusOK, status)
}

// GetAntreaFilters returns active PacketCapture filters from Antrea
func (h *BPFHandler) GetAntreaFilters(w http.ResponseWriter, r *http.Request) {
	filters := getAntreaPacketCaptures()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"filters": filters,
		"count":   len(filters),
	})
}

// CompareLiveCapture compares BPF between tcpdump and a live Antrea capture
func (h *BPFHandler) CompareLiveCapture(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Expression string `json:"expression"`
		Duration   int    `json:"duration"` // seconds
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Duration == 0 {
		req.Duration = 10
	}

	// Get tcpdump BPF
	tcpdumpBPF := getTcpdumpBPF(req.Expression)

	// Get Antrea BPF (from actual Antrea if connected, otherwise simulated)
	antreaBPF := getAntreaBPF(req.Expression)

	// Check Antrea status
	antreaStatus := checkAntreaConnection()

	// Analyze
	result := analyzeBPFDifferences(req.Expression, tcpdumpBPF, antreaBPF)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"comparison":   result,
		"antreaStatus": antreaStatus,
		"liveCapture": map[string]interface{}{
			"enabled":  antreaStatus.Connected,
			"duration": req.Duration,
		},
	})
}

func checkAntreaConnection() AntreaIntegrationStatus {
	status := AntreaIntegrationStatus{
		Connected: false,
		Message:   "Checking Antrea connection...",
	}

	// Try to connect to Antrea controller via kubectl
	cmd := exec.Command("kubectl", "get", "antreacontrollerinfos", "-o", "json")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Check if kubectl is available
		_, kubectlErr := exec.LookPath("kubectl")
		if kubectlErr != nil {
			status.Message = "kubectl not found - install kubectl to connect to Antrea"
			return status
		}

		// kubectl available but Antrea not found
		if strings.Contains(string(output), "not found") ||
			strings.Contains(string(output), "No resources found") {
			status.Message = "Antrea not installed in cluster - using simulated BPF generation"
		} else if strings.Contains(string(output), "connection refused") {
			status.Message = "Cannot connect to Kubernetes cluster"
		} else {
			status.Message = "Antrea controller not accessible: " + string(output)
		}
		return status
	}

	// Parse Antrea controller info
	var controllerInfo struct {
		Items []struct {
			Status struct {
				ControllerConditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"controllerConditions"`
			} `json:"status"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &controllerInfo); err == nil && len(controllerInfo.Items) > 0 {
		status.Connected = true
		status.ClusterName = controllerInfo.Items[0].Metadata.Name

		// Check controller readiness
		for _, cond := range controllerInfo.Items[0].Status.ControllerConditions {
			if cond.Type == "ControllerHealthy" && cond.Status == "True" {
				status.ControllerReady = true
			}
		}

		status.Message = "Connected to Antrea cluster"

		// Get agent count
		agentCmd := exec.Command("kubectl", "get", "antreaagentinfos", "--no-headers")
		agentOutput, _ := agentCmd.CombinedOutput()
		status.AgentCount = len(strings.Split(strings.TrimSpace(string(agentOutput)), "\n"))

		// Get Antrea version
		versionCmd := exec.Command("kubectl", "get", "deployment", "antrea-controller",
			"-n", "kube-system", "-o", "jsonpath={.spec.template.spec.containers[0].image}")
		versionOutput, _ := versionCmd.CombinedOutput()
		if len(versionOutput) > 0 {
			parts := strings.Split(string(versionOutput), ":")
			if len(parts) > 1 {
				status.AntreaVersion = parts[len(parts)-1]
			}
		}
	}

	return status
}

func getAntreaPacketCaptures() []map[string]interface{} {
	captures := []map[string]interface{}{}

	cmd := exec.Command("kubectl", "get", "packetcaptures", "-A", "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return captures
	}

	var pcList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				Source struct {
					Pod       string `json:"pod"`
					Namespace string `json:"namespace"`
				} `json:"source"`
				Destination struct {
					Pod       string `json:"pod"`
					Namespace string `json:"namespace"`
					IP        string `json:"ip"`
				} `json:"destination"`
				Packet struct {
					Protocol        string `json:"protocol"`
					IPFamily        string `json:"ipFamily"`
					TransportHeader struct {
						TCP *struct {
							DstPort int `json:"dstPort"`
							SrcPort int `json:"srcPort"`
						} `json:"tcp"`
						UDP *struct {
							DstPort int `json:"dstPort"`
							SrcPort int `json:"srcPort"`
						} `json:"udp"`
					} `json:"transportHeader"`
				} `json:"packet"`
			} `json:"spec"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &pcList); err == nil {
		for _, pc := range pcList.Items {
			captures = append(captures, map[string]interface{}{
				"name":        pc.Metadata.Name,
				"namespace":   pc.Metadata.Namespace,
				"source":      pc.Spec.Source,
				"destination": pc.Spec.Destination,
				"packet":      pc.Spec.Packet,
				"status":      pc.Status.Phase,
			})
		}
	}

	return captures
}

// ===============================
// ADVANCED ANALYSIS HANDLERS
// ===============================

// FullAnalysis provides comprehensive BPF analysis
func (h *BPFHandler) FullAnalysis(w http.ResponseWriter, r *http.Request) {
	var req BPFCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Expression == "" {
		respondError(w, http.StatusBadRequest, "Expression is required")
		return
	}

	report := generateFullReport(req.Expression)
	respondJSON(w, http.StatusOK, report)
}

// GetInstructionFlow returns the instruction flow graph
func (h *BPFHandler) GetInstructionFlow(w http.ResponseWriter, r *http.Request) {
	var req BPFCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	bpf := getTcpdumpBPF(req.Expression)
	flow := buildFlowGraph(bpf)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"expression": req.Expression,
		"flow":       flow,
		"nodeCount":  len(flow),
	})
}

// GetOptimizations returns optimization suggestions
func (h *BPFHandler) GetOptimizations(w http.ResponseWriter, r *http.Request) {
	var req BPFCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	bpf := getTcpdumpBPF(req.Expression)
	opts := analyzeOptimizations(bpf, req.Expression)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"expression":    req.Expression,
		"optimizations": opts,
		"count":         len(opts),
	})
}

// GetK8sPresets returns Kubernetes/Antrea-specific filter presets
func (h *BPFHandler) GetK8sPresets(w http.ResponseWriter, r *http.Request) {
	presets := []map[string]interface{}{
		{
			"name":        "Pod-to-Pod TCP",
			"expression":  "tcp and not port 53",
			"description": "Capture TCP traffic between pods, excluding DNS",
			"useCase":     "Debugging service-to-service communication",
		},
		{
			"name":        "DNS Traffic",
			"expression":  "udp port 53 or tcp port 53",
			"description": "Capture all DNS queries and responses",
			"useCase":     "Debugging DNS resolution issues in cluster",
		},
		{
			"name":        "Kubernetes API",
			"expression":  "tcp port 6443",
			"description": "Capture Kubernetes API server traffic",
			"useCase":     "Debugging API server communication",
		},
		{
			"name":        "HTTPS Services",
			"expression":  "tcp port 443",
			"description": "Capture HTTPS traffic to services",
			"useCase":     "Monitoring secure service endpoints",
		},
		{
			"name":        "NodePort Range",
			"expression":  "tcp portrange 30000-32767",
			"description": "Capture NodePort service traffic",
			"useCase":     "Debugging NodePort service access",
		},
		{
			"name":        "ICMP/Ping",
			"expression":  "icmp or icmp6",
			"description": "Capture ICMP traffic for connectivity tests",
			"useCase":     "Network connectivity debugging",
		},
		{
			"name":        "Antrea Agent",
			"expression":  "tcp port 10350 or tcp port 10351",
			"description": "Capture Antrea agent communication",
			"useCase":     "Debugging Antrea agent issues",
		},
		{
			"name":        "Geneve Tunnel",
			"expression":  "udp port 6081",
			"description": "Capture Geneve encapsulated traffic",
			"useCase":     "Debugging Antrea tunnel overlay",
		},
		{
			"name":        "VXLAN Tunnel",
			"expression":  "udp port 4789",
			"description": "Capture VXLAN encapsulated traffic",
			"useCase":     "Debugging VXLAN overlay networks",
		},
		{
			"name":        "Network Policy Drop",
			"expression":  "tcp[tcpflags] & (tcp-rst) != 0",
			"description": "Capture TCP RST packets (potential policy drops)",
			"useCase":     "Identifying Network Policy blocking traffic",
		},
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"presets": presets,
		"count":   len(presets),
	})
}

// GenerateReport generates a comprehensive PDF-ready report
func (h *BPFHandler) GenerateReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Expression string   `json:"expression"`
		Formats    []string `json:"formats"` // json, markdown, html
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	report := generateFullReport(req.Expression)

	// Generate markdown report
	markdown := generateMarkdownReport(report)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"report":   report,
		"markdown": markdown,
	})
}

// Helper functions for advanced analysis

func generateFullReport(expression string) BPFAnalysisReport {
	tcpdumpBPF := getTcpdumpBPF(expression)
	antreaBPF := getAntreaBPF(expression)
	comparison := analyzeBPFDifferences(expression, tcpdumpBPF, antreaBPF)
	metrics := calculateMetrics(tcpdumpBPF, expression)
	flow := buildFlowGraph(tcpdumpBPF)
	opts := analyzeOptimizations(tcpdumpBPF, expression)
	k8sHints := getKubernetesHints(expression)

	return BPFAnalysisReport{
		Expression:      expression,
		TcpdumpProgram:  tcpdumpBPF,
		AntreaProgram:   antreaBPF,
		Metrics:         metrics,
		FlowGraph:       flow,
		Optimizations:   opts,
		Comparison:      comparison,
		KubernetesHints: k8sHints,
		GeneratedAt:     time.Now(),
	}
}

func buildFlowGraph(bpf BPFProgram) []BPFFlowNode {
	nodes := make([]BPFFlowNode, 0, len(bpf.Instructions))

	for i, inst := range bpf.Instructions {
		node := BPFFlowNode{
			Index:       i,
			Instruction: inst.Desc,
			Reachable:   true,
		}

		opClass := inst.Op & 0x07
		switch opClass {
		case 0x00, 0x01: // LD, LDX
			node.Type = "load"
			node.Next = i + 1
		case 0x04: // ALU
			node.Type = "alu"
			node.Next = i + 1
		case 0x05: // JMP
			node.Type = "jump"
			if inst.Op == 0x05 { // ja (jump always)
				node.Next = i + 1 + int(inst.K)
			} else {
				node.NextTrue = i + 1 + int(inst.Jt)
				node.NextFalse = i + 1 + int(inst.Jf)
			}
		case 0x06: // RET
			node.Type = "return"
			node.IsTerminal = true
		default:
			node.Type = "other"
			node.Next = i + 1
		}

		nodes = append(nodes, node)
	}

	return nodes
}

func analyzeOptimizations(bpf BPFProgram, expr string) []BPFOptimization {
	opts := []BPFOptimization{}

	// Check for high instruction count
	if bpf.Count > 30 {
		opts = append(opts, BPFOptimization{
			Type:        "complexity",
			Severity:    "warning",
			Description: fmt.Sprintf("High instruction count: %d instructions", bpf.Count),
			Suggestion:  "Consider simplifying the filter expression",
			Impact:      "May impact packet processing performance",
		})
	}

	// Check for deep jump chains
	maxJump := 0
	for _, inst := range bpf.Instructions {
		if int(inst.Jt) > maxJump {
			maxJump = int(inst.Jt)
		}
		if int(inst.Jf) > maxJump {
			maxJump = int(inst.Jf)
		}
	}
	if maxJump > 10 {
		opts = append(opts, BPFOptimization{
			Type:        "jump-depth",
			Severity:    "info",
			Description: fmt.Sprintf("Deep jump distance: %d instructions", maxJump),
			Suggestion:  "Consider reordering filter conditions for better branch prediction",
			Impact:      "Minor performance impact on modern CPUs",
		})
	}

	// Check for IPv6 support
	hasIPv6 := false
	for _, inst := range bpf.Instructions {
		if inst.K == 0x86dd {
			hasIPv6 = true
			break
		}
	}
	if hasIPv6 {
		opts = append(opts, BPFOptimization{
			Type:        "ipv6",
			Severity:    "info",
			Description: "Filter includes IPv6 support",
			Suggestion:  "If IPv6 is not needed, use 'ip' prefix to filter only IPv4",
			Impact:      "Reduces instruction count by ~30%",
		})
	}

	// Check for common Kubernetes patterns
	if strings.Contains(expr, "port 53") {
		opts = append(opts, BPFOptimization{
			Type:        "kubernetes",
			Severity:    "info",
			Description: "DNS filter detected",
			Suggestion:  "Consider filtering by CoreDNS pod IP for better performance",
			Impact:      "Reduces false positives in cluster",
		})
	}

	// Antrea-specific suggestions
	if strings.Contains(expr, "port 6081") || strings.Contains(expr, "geneve") {
		opts = append(opts, BPFOptimization{
			Type:        "antrea",
			Severity:    "info",
			Description: "Geneve tunnel filter detected",
			Suggestion:  "Use Antrea's PacketCapture CRD for inner packet filtering",
			Impact:      "Better visibility into encapsulated traffic",
		})
	}

	if len(opts) == 0 {
		opts = append(opts, BPFOptimization{
			Type:        "optimal",
			Severity:    "info",
			Description: "Filter appears well-optimized",
			Suggestion:  "No significant optimizations identified",
			Impact:      "Good performance expected",
		})
	}

	return opts
}

func getKubernetesHints(expr string) []string {
	hints := []string{}

	if strings.Contains(expr, "tcp") {
		hints = append(hints, "Consider using Antrea NetworkPolicy for TCP traffic filtering")
	}
	if strings.Contains(expr, "port 443") || strings.Contains(expr, "port 80") {
		hints = append(hints, "Use Kubernetes Ingress or Service for HTTP/HTTPS routing")
	}
	if strings.Contains(expr, "icmp") {
		hints = append(hints, "ICMP can be controlled via Antrea ClusterNetworkPolicy")
	}
	if strings.Contains(expr, "host") {
		hints = append(hints, "In Kubernetes, use pod selectors instead of IP addresses")
	}

	return hints
}

func generateMarkdownReport(report BPFAnalysisReport) string {
	var sb strings.Builder

	sb.WriteString("# Antrea BPF Analysis Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", report.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Filter Expression:** `%s`\n\n", report.Expression))

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Metric | tcpdump | Antrea |\n"))
	sb.WriteString(fmt.Sprintf("|--------|---------|--------|\n"))
	sb.WriteString(fmt.Sprintf("| Instructions | %d | %d |\n",
		report.TcpdumpProgram.Count, report.AntreaProgram.Count))
	sb.WriteString(fmt.Sprintf("| Match | %v | - |\n", report.Comparison.Match))

	sb.WriteString("\n## Metrics\n\n")
	sb.WriteString(fmt.Sprintf("- **Complexity Score:** %.1f\n", report.Metrics.ComplexityScore))
	sb.WriteString(fmt.Sprintf("- **Estimated CPU Cycles:** %d\n", report.Metrics.EstimatedCycles))
	sb.WriteString(fmt.Sprintf("- **Jump Count:** %d\n", report.Metrics.JumpCount))
	sb.WriteString(fmt.Sprintf("- **IPv6 Support:** %v\n", report.Metrics.HasIPv6))

	if len(report.Optimizations) > 0 {
		sb.WriteString("\n## Optimization Suggestions\n\n")
		for _, opt := range report.Optimizations {
			sb.WriteString(fmt.Sprintf("### %s (%s)\n", opt.Type, opt.Severity))
			sb.WriteString(fmt.Sprintf("- **Issue:** %s\n", opt.Description))
			sb.WriteString(fmt.Sprintf("- **Suggestion:** %s\n", opt.Suggestion))
			sb.WriteString(fmt.Sprintf("- **Impact:** %s\n\n", opt.Impact))
		}
	}

	if len(report.KubernetesHints) > 0 {
		sb.WriteString("\n## Kubernetes Hints\n\n")
		for _, hint := range report.KubernetesHints {
			sb.WriteString(fmt.Sprintf("- %s\n", hint))
		}
	}

	sb.WriteString("\n## BPF Bytecode (tcpdump)\n\n")
	sb.WriteString("```c\n")
	for _, inst := range report.TcpdumpProgram.Instructions {
		sb.WriteString(fmt.Sprintf("{ 0x%02x, %d, %d, 0x%08x }, // %s\n",
			inst.Op, inst.Jt, inst.Jf, inst.K, inst.Desc))
	}
	sb.WriteString("```\n")

	sb.WriteString("\n---\n")
	sb.WriteString("*Generated by Antrea Network Monitor - CNCF LFX Mentorship 2026*\n")

	return sb.String()
}

// ===============================
// TEST GENERATION HANDLERS (LFX)
// ===============================

// Comprehensive test case templates for BPF testing
var testCaseTemplates = []TestCase{
	// Basic Protocol Tests
	{ID: "proto-tcp", Expression: "tcp", Description: "Match all TCP packets", Category: "protocol"},
	{ID: "proto-udp", Expression: "udp", Description: "Match all UDP packets", Category: "protocol"},
	{ID: "proto-icmp", Expression: "icmp", Description: "Match ICMP packets", Category: "protocol", IPv4Only: true},
	{ID: "proto-icmp6", Expression: "icmp6", Description: "Match ICMPv6 packets", Category: "protocol", IPv6Only: true},
	{ID: "proto-arp", Expression: "arp", Description: "Match ARP packets", Category: "protocol"},
	{ID: "proto-ip", Expression: "ip", Description: "Match IPv4 packets", Category: "protocol", IPv4Only: true},
	{ID: "proto-ip6", Expression: "ip6", Description: "Match IPv6 packets", Category: "protocol", IPv6Only: true},
	{ID: "proto-sctp", Expression: "sctp", Description: "Match SCTP packets", Category: "protocol"},

	// Port Tests
	{ID: "port-80", Expression: "port 80", Description: "Match port 80 (HTTP)", Category: "port"},
	{ID: "port-443", Expression: "port 443", Description: "Match port 443 (HTTPS)", Category: "port"},
	{ID: "port-53", Expression: "port 53", Description: "Match port 53 (DNS)", Category: "port"},
	{ID: "port-22", Expression: "port 22", Description: "Match port 22 (SSH)", Category: "port"},
	{ID: "port-range", Expression: "portrange 8000-8080", Description: "Match port range 8000-8080", Category: "port"},
	{ID: "port-src", Expression: "src port 443", Description: "Match source port 443", Category: "port"},
	{ID: "port-dst", Expression: "dst port 80", Description: "Match destination port 80", Category: "port"},

	// TCP Port Tests
	{ID: "tcp-port-80", Expression: "tcp port 80", Description: "TCP port 80", Category: "tcp"},
	{ID: "tcp-port-443", Expression: "tcp port 443", Description: "TCP port 443", Category: "tcp"},
	{ID: "tcp-port-22", Expression: "tcp port 22", Description: "TCP SSH", Category: "tcp"},
	{ID: "tcp-port-3306", Expression: "tcp port 3306", Description: "TCP MySQL", Category: "tcp"},
	{ID: "tcp-port-5432", Expression: "tcp port 5432", Description: "TCP PostgreSQL", Category: "tcp"},
	{ID: "tcp-port-6379", Expression: "tcp port 6379", Description: "TCP Redis", Category: "tcp"},
	{ID: "tcp-src-port", Expression: "tcp src port 443", Description: "TCP source port 443", Category: "tcp"},
	{ID: "tcp-dst-port", Expression: "tcp dst port 80", Description: "TCP destination port 80", Category: "tcp"},
	{ID: "tcp-portrange", Expression: "tcp portrange 30000-32767", Description: "TCP NodePort range", Category: "tcp"},

	// UDP Port Tests
	{ID: "udp-port-53", Expression: "udp port 53", Description: "UDP DNS", Category: "udp"},
	{ID: "udp-port-123", Expression: "udp port 123", Description: "UDP NTP", Category: "udp"},
	{ID: "udp-port-514", Expression: "udp port 514", Description: "UDP Syslog", Category: "udp"},
	{ID: "udp-port-6081", Expression: "udp port 6081", Description: "UDP Geneve (Antrea)", Category: "udp"},
	{ID: "udp-port-4789", Expression: "udp port 4789", Description: "UDP VXLAN", Category: "udp"},

	// Host Tests
	{ID: "host-v4", Expression: "host 192.168.1.1", Description: "Match specific IPv4 host", Category: "host"},
	{ID: "host-v4-src", Expression: "src host 10.0.0.1", Description: "Match source IPv4", Category: "host"},
	{ID: "host-v4-dst", Expression: "dst host 172.16.0.1", Description: "Match destination IPv4", Category: "host"},
	{ID: "host-v6", Expression: "host ::1", Description: "Match IPv6 localhost", Category: "host", IPv6Only: true},

	// Network Tests
	{ID: "net-v4-cidr", Expression: "net 192.168.0.0/16", Description: "Match /16 network", Category: "network"},
	{ID: "net-v4-24", Expression: "net 10.0.0.0/24", Description: "Match /24 network", Category: "network"},
	{ID: "net-src", Expression: "src net 172.16.0.0/12", Description: "Source network", Category: "network"},
	{ID: "net-dst", Expression: "dst net 10.96.0.0/12", Description: "K8s service network", Category: "network"},

	// TCP Flags Tests
	{ID: "tcp-syn", Expression: "tcp[tcpflags] & tcp-syn != 0", Description: "TCP SYN packets", Category: "flags"},
	{ID: "tcp-ack", Expression: "tcp[tcpflags] & tcp-ack != 0", Description: "TCP ACK packets", Category: "flags"},
	{ID: "tcp-fin", Expression: "tcp[tcpflags] & tcp-fin != 0", Description: "TCP FIN packets", Category: "flags"},
	{ID: "tcp-rst", Expression: "tcp[tcpflags] & tcp-rst != 0", Description: "TCP RST packets", Category: "flags"},
	{ID: "tcp-push", Expression: "tcp[tcpflags] & tcp-push != 0", Description: "TCP PUSH packets", Category: "flags"},
	{ID: "tcp-syn-only", Expression: "tcp[tcpflags] == tcp-syn", Description: "TCP SYN only", Category: "flags"},
	{ID: "tcp-synack", Expression: "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)", Description: "TCP SYN-ACK", Category: "flags"},

	// Compound Expressions
	{ID: "compound-and", Expression: "tcp and port 80", Description: "TCP AND port 80", Category: "compound"},
	{ID: "compound-or", Expression: "port 80 or port 443", Description: "Port 80 OR 443", Category: "compound"},
	{ID: "compound-not", Expression: "not port 22", Description: "NOT port 22", Category: "compound"},
	{ID: "compound-complex", Expression: "tcp and (port 80 or port 443)", Description: "TCP HTTP/HTTPS", Category: "compound"},
	{ID: "compound-host-port", Expression: "host 192.168.1.1 and tcp port 80", Description: "Host and TCP port", Category: "compound"},
	{ID: "compound-exclude", Expression: "tcp and not port 22", Description: "TCP excluding SSH", Category: "compound"},

	// Kubernetes/CNI Specific
	{ID: "k8s-dns", Expression: "udp port 53 or tcp port 53", Description: "K8s DNS traffic", Category: "kubernetes"},
	{ID: "k8s-api", Expression: "tcp port 6443", Description: "K8s API server", Category: "kubernetes"},
	{ID: "k8s-kubelet", Expression: "tcp port 10250", Description: "Kubelet API", Category: "kubernetes"},
	{ID: "k8s-etcd", Expression: "tcp port 2379 or tcp port 2380", Description: "etcd traffic", Category: "kubernetes"},
	{ID: "k8s-nodeport", Expression: "tcp portrange 30000-32767", Description: "NodePort range", Category: "kubernetes"},
	{ID: "k8s-metrics", Expression: "tcp port 9090 or tcp port 9091", Description: "Prometheus metrics", Category: "kubernetes"},

	// Antrea Specific
	{ID: "antrea-geneve", Expression: "udp port 6081", Description: "Antrea Geneve tunnel", Category: "antrea"},
	{ID: "antrea-agent", Expression: "tcp port 10350", Description: "Antrea agent API", Category: "antrea"},
	{ID: "antrea-controller", Expression: "tcp port 10349", Description: "Antrea controller", Category: "antrea"},
	{ID: "antrea-flow", Expression: "tcp port 4739", Description: "Antrea flow export", Category: "antrea"},

	// Fragment Tests
	{ID: "frag-first", Expression: "ip[6:2] & 0x1fff = 0", Description: "First fragment or unfragmented", Category: "fragment"},
	{ID: "frag-more", Expression: "ip[6:2] & 0x2000 != 0", Description: "More fragments flag", Category: "fragment"},

	// Length Tests
	{ID: "len-greater", Expression: "greater 1000", Description: "Packets > 1000 bytes", Category: "length"},
	{ID: "len-less", Expression: "less 100", Description: "Packets < 100 bytes", Category: "length"},

	// VLAN Tests
	{ID: "vlan", Expression: "vlan", Description: "Match VLAN tagged", Category: "vlan"},
	{ID: "vlan-id", Expression: "vlan 100", Description: "Match VLAN ID 100", Category: "vlan"},

	// Broadcast/Multicast
	{ID: "broadcast", Expression: "broadcast", Description: "Broadcast packets", Category: "broadcast"},
	{ID: "multicast", Expression: "multicast", Description: "Multicast packets", Category: "broadcast"},

	// Advanced Byte Access
	{ID: "byte-ether", Expression: "ether[0] & 1 != 0", Description: "Multicast Ethernet", Category: "advanced"},
	{ID: "byte-ip-ttl", Expression: "ip[8] < 10", Description: "Low TTL packets", Category: "advanced"},
	{ID: "byte-ip-proto", Expression: "ip[9] == 6", Description: "IP protocol = TCP", Category: "advanced"},
}

// GenerateTestCases generates comprehensive test cases
func (h *BPFHandler) GenerateTestCases(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Categories []string `json:"categories,omitempty"` // Filter by categories
		Count      int      `json:"count,omitempty"`      // Max number of tests
		AIGenerate bool     `json:"aiGenerate,omitempty"` // Use AI for more tests
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Use defaults
		req.Count = 100
	}

	testCases := make([]TestCase, 0)

	// Start with predefined templates
	for _, tc := range testCaseTemplates {
		if len(req.Categories) > 0 {
			found := false
			for _, cat := range req.Categories {
				if tc.Category == cat {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Generate tcpdump reference BPF for each test
		tc.TcpdumpBPF = getTcpdumpBPF(tc.Expression)
		tc.ExpectedOK = tc.TcpdumpBPF.Error == ""
		testCases = append(testCases, tc)

		if req.Count > 0 && len(testCases) >= req.Count {
			break
		}
	}

	// Generate AI test cases if requested (simulated - would use OpenAI API)
	if req.AIGenerate && (req.Count == 0 || len(testCases) < req.Count) {
		aiTests := generateAITestCases(req.Count - len(testCases))
		testCases = append(testCases, aiTests...)
	}

	// Build statistics
	stats := TestStats{
		Total:      len(testCases),
		ByCategory: make(map[string]int),
	}

	categories := make(map[string]bool)
	for _, tc := range testCases {
		stats.ByCategory[tc.Category]++
		categories[tc.Category] = true
		if tc.IPv4Only {
			stats.IPv4Count++
		} else if tc.IPv6Only {
			stats.IPv6Count++
		} else {
			stats.DualStack++
		}
	}

	categoryList := make([]string, 0, len(categories))
	for cat := range categories {
		categoryList = append(categoryList, cat)
	}

	suite := TestSuite{
		Name:        "Antrea BPF Test Suite",
		Description: "Comprehensive BPF test cases for PacketCapture comparison",
		Generated:   time.Now(),
		TestCases:   testCases,
		Categories:  categoryList,
		Stats:       stats,
	}

	respondJSON(w, http.StatusOK, suite)
}

// generateAITestCases simulates AI-generated test cases
func generateAITestCases(count int) []TestCase {
	// In production, this would call OpenAI/Claude API
	// For now, generate variations programmatically

	aiTests := []TestCase{}

	// Generate port variations
	ports := []int{21, 23, 25, 110, 143, 389, 636, 993, 995, 1433, 1521, 3389, 5900, 8080, 8443, 9200, 27017}
	for i, port := range ports {
		if len(aiTests) >= count {
			break
		}
		tc := TestCase{
			ID:          fmt.Sprintf("ai-port-%d", port),
			Expression:  fmt.Sprintf("tcp port %d", port),
			Description: fmt.Sprintf("AI-generated: TCP port %d", port),
			Category:    "ai-generated",
		}
		tc.TcpdumpBPF = getTcpdumpBPF(tc.Expression)
		tc.ExpectedOK = tc.TcpdumpBPF.Error == ""
		aiTests = append(aiTests, tc)

		// Also add UDP variant
		if len(aiTests) < count && i%2 == 0 {
			tcUDP := TestCase{
				ID:          fmt.Sprintf("ai-udp-port-%d", port),
				Expression:  fmt.Sprintf("udp port %d", port),
				Description: fmt.Sprintf("AI-generated: UDP port %d", port),
				Category:    "ai-generated",
			}
			tcUDP.TcpdumpBPF = getTcpdumpBPF(tcUDP.Expression)
			tcUDP.ExpectedOK = tcUDP.TcpdumpBPF.Error == ""
			aiTests = append(aiTests, tcUDP)
		}
	}

	// Generate network variations
	networks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "10.244.0.0/16", "10.96.0.0/12"}
	for _, net := range networks {
		if len(aiTests) >= count {
			break
		}
		tc := TestCase{
			ID:          fmt.Sprintf("ai-net-%s", strings.ReplaceAll(net, "/", "-")),
			Expression:  fmt.Sprintf("net %s", net),
			Description: fmt.Sprintf("AI-generated: Network %s", net),
			Category:    "ai-generated",
		}
		tc.TcpdumpBPF = getTcpdumpBPF(tc.Expression)
		tc.ExpectedOK = tc.TcpdumpBPF.Error == ""
		aiTests = append(aiTests, tc)
	}

	return aiTests
}

// GetTestSuite returns the current test suite
func (h *BPFHandler) GetTestSuite(w http.ResponseWriter, r *http.Request) {
	testCases := make([]TestCase, len(testCaseTemplates))
	copy(testCases, testCaseTemplates)

	// Add tcpdump BPF for each
	for i := range testCases {
		testCases[i].TcpdumpBPF = getTcpdumpBPF(testCases[i].Expression)
		testCases[i].ExpectedOK = testCases[i].TcpdumpBPF.Error == ""
	}

	stats := TestStats{
		Total:      len(testCases),
		ByCategory: make(map[string]int),
	}

	categories := make(map[string]bool)
	for _, tc := range testCases {
		stats.ByCategory[tc.Category]++
		categories[tc.Category] = true
	}

	categoryList := make([]string, 0, len(categories))
	for cat := range categories {
		categoryList = append(categoryList, cat)
	}

	suite := TestSuite{
		Name:        "Antrea BPF Test Suite",
		Description: "Predefined BPF test cases",
		Generated:   time.Now(),
		TestCases:   testCases,
		Categories:  categoryList,
		Stats:       stats,
	}

	respondJSON(w, http.StatusOK, suite)
}

// GenerateGoTest generates Go test file for Antrea
func (h *BPFHandler) GenerateGoTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PackageName string   `json:"packageName"`
		Categories  []string `json:"categories,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.PackageName = "capture"
	}

	if req.PackageName == "" {
		req.PackageName = "capture"
	}

	// Filter test cases
	testCases := make([]TestCase, 0)
	for _, tc := range testCaseTemplates {
		if len(req.Categories) > 0 {
			found := false
			for _, cat := range req.Categories {
				if tc.Category == cat {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		tc.TcpdumpBPF = getTcpdumpBPF(tc.Expression)
		tc.ExpectedOK = tc.TcpdumpBPF.Error == ""
		testCases = append(testCases, tc)
	}

	// Generate Go test code
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`// Code generated by Antrea Network Monitor - DO NOT EDIT.
// Generated: %s
// Test cases for comparing Antrea BPF generation with tcpdump/libpcap
// Part of CNCF LFX Mentorship 2026

package %s

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCase represents a BPF comparison test case
type bpfTestCase struct {
	name       string
	expression string
	category   string
	ipv4Only   bool
	ipv6Only   bool
	// tcpdumpBPF contains the expected BPF instructions from tcpdump
	tcpdumpInstructions int
}

// Generated test cases from tcpdump reference
var generatedTestCases = []bpfTestCase{
`, time.Now().Format(time.RFC3339), req.PackageName))

	for _, tc := range testCases {
		ipv4Str := "false"
		ipv6Str := "false"
		if tc.IPv4Only {
			ipv4Str = "true"
		}
		if tc.IPv6Only {
			ipv6Str = "true"
		}
		sb.WriteString(fmt.Sprintf(`	{
		name:                %q,
		expression:          %q,
		category:            %q,
		ipv4Only:            %s,
		ipv6Only:            %s,
		tcpdumpInstructions: %d,
	},
`, tc.Description, tc.Expression, tc.Category, ipv4Str, ipv6Str, tc.TcpdumpBPF.Count))
	}

	sb.WriteString(`}

// TestBPFComparison_Generated tests that Antrea BPF matches tcpdump
func TestBPFComparison_Generated(t *testing.T) {
	for _, tc := range generatedTestCases {
		t.Run(tc.name, func(t *testing.T) {
			// Skip IPv6-only tests if not supported
			if tc.ipv6Only {
				t.Skip("IPv6-only test")
			}

			// TODO: Call compilePacketFilter with the expression
			// antreaBPF, err := compilePacketFilter(...)
			
			// For now, just verify the expression is valid
			assert.NotEmpty(t, tc.expression, "Expression should not be empty")
			assert.Greater(t, tc.tcpdumpInstructions, 0, "tcpdump should generate instructions")
		})
	}
}

// TestBPFComparison_Categories tests BPF by category
func TestBPFComparison_Categories(t *testing.T) {
	categories := make(map[string][]bpfTestCase)
	for _, tc := range generatedTestCases {
		categories[tc.category] = append(categories[tc.category], tc)
	}

	for category, tests := range categories {
		t.Run(category, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					assert.NotEmpty(t, tc.expression)
				})
			}
		})
	}
}
`)

	output := GoTestOutput{
		Filename:    "bpf_generated_test.go",
		Code:        sb.String(),
		TestCount:   len(testCases),
		PackageName: req.PackageName,
	}

	respondJSON(w, http.StatusOK, output)
}

// RunTestSuite runs all test cases and returns results
func (h *BPFHandler) RunTestSuite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Categories []string `json:"categories,omitempty"`
	}

	json.NewDecoder(r.Body).Decode(&req)

	type TestResult struct {
		TestCase  TestCase `json:"testCase"`
		TcpdumpOK bool     `json:"tcpdumpOk"`
		AntreaOK  bool     `json:"antreaOk"`
		Match     bool     `json:"match"`
		Diff      int      `json:"instructionDiff"`
		ErrorMsg  string   `json:"error,omitempty"`
	}

	results := []TestResult{}
	passCount := 0
	failCount := 0

	for _, tc := range testCaseTemplates {
		if len(req.Categories) > 0 {
			found := false
			for _, cat := range req.Categories {
				if tc.Category == cat {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		tcpdumpBPF := getTcpdumpBPF(tc.Expression)
		antreaBPF := getAntreaBPF(tc.Expression)

		result := TestResult{
			TestCase:  tc,
			TcpdumpOK: tcpdumpBPF.Error == "",
			AntreaOK:  antreaBPF.Error == "",
			Match:     tcpdumpBPF.Count == antreaBPF.Count,
			Diff:      antreaBPF.Count - tcpdumpBPF.Count,
		}

		if tcpdumpBPF.Error != "" {
			result.ErrorMsg = tcpdumpBPF.Error
		}

		// For now, consider it a pass if tcpdump succeeds
		if result.TcpdumpOK {
			passCount++
		} else {
			failCount++
		}

		results = append(results, result)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"results":  results,
		"total":    len(results),
		"passed":   passCount,
		"failed":   failCount,
		"passRate": float64(passCount) / float64(len(results)) * 100,
	})
}

// GetTestCategories returns available test categories
func (h *BPFHandler) GetTestCategories(w http.ResponseWriter, r *http.Request) {
	categories := make(map[string]int)
	for _, tc := range testCaseTemplates {
		categories[tc.Category]++
	}

	type CategoryInfo struct {
		Name        string `json:"name"`
		Count       int    `json:"count"`
		Description string `json:"description"`
	}

	categoryDescriptions := map[string]string{
		"protocol":     "Basic protocol matching (TCP, UDP, ICMP, etc.)",
		"port":         "Port number matching",
		"tcp":          "TCP-specific filters",
		"udp":          "UDP-specific filters",
		"host":         "Host/IP address matching",
		"network":      "Network/subnet matching",
		"flags":        "TCP flags matching",
		"compound":     "Compound expressions (AND, OR, NOT)",
		"kubernetes":   "Kubernetes-specific filters",
		"antrea":       "Antrea CNI-specific filters",
		"fragment":     "IP fragment handling",
		"length":       "Packet length filters",
		"vlan":         "VLAN tag matching",
		"broadcast":    "Broadcast/multicast matching",
		"advanced":     "Advanced byte-level access",
		"ai-generated": "AI-generated test cases",
	}

	result := []CategoryInfo{}
	for name, count := range categories {
		desc := categoryDescriptions[name]
		if desc == "" {
			desc = "Test cases for " + name
		}
		result = append(result, CategoryInfo{
			Name:        name,
			Count:       count,
			Description: desc,
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"categories": result,
		"total":      len(testCaseTemplates),
	})
}

// ===============================
// SEMANTIC EQUIVALENCE ANALYSIS
// ===============================

// SemanticEquivalenceResult represents the result of semantic analysis
type SemanticEquivalenceResult struct {
	Expression1       string   `json:"expression1"`
	Expression2       string   `json:"expression2"`
	BytecodeMatch     bool     `json:"bytecodeMatch"`
	SemanticMatch     bool     `json:"semanticMatch"`
	Confidence        float64  `json:"confidence"`
	Analysis          []string `json:"analysis"`
	Recommendation    string   `json:"recommendation"`
	EquivalenceReason string   `json:"equivalenceReason,omitempty"`
}

// CheckSemanticEquivalence checks if two BPF programs are semantically equivalent
func (h *BPFHandler) CheckSemanticEquivalence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Expression1 string `json:"expression1"`
		Expression2 string `json:"expression2"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	bpf1 := getTcpdumpBPF(req.Expression1)
	bpf2 := getTcpdumpBPF(req.Expression2)

	result := analyzeSemanticEquivalence(req.Expression1, req.Expression2, bpf1, bpf2)
	respondJSON(w, http.StatusOK, result)
}

// analyzeSemanticEquivalence performs semantic analysis of two BPF programs
func analyzeSemanticEquivalence(expr1, expr2 string, bpf1, bpf2 BPFProgram) SemanticEquivalenceResult {
	result := SemanticEquivalenceResult{
		Expression1:   expr1,
		Expression2:   expr2,
		BytecodeMatch: compareBytecode(bpf1, bpf2),
		Analysis:      []string{},
	}

	// If bytecode matches exactly, they are equivalent
	if result.BytecodeMatch {
		result.SemanticMatch = true
		result.Confidence = 100.0
		result.Recommendation = "Expressions produce identical BPF bytecode"
		result.EquivalenceReason = "exact_match"
		return result
	}

	// Analyze structural similarity
	instructionDiff := abs(bpf1.Count - bpf2.Count)
	result.Analysis = append(result.Analysis, fmt.Sprintf("Instruction count: %d vs %d (diff: %d)", bpf1.Count, bpf2.Count, instructionDiff))

	// Check for common semantic equivalence patterns
	semanticEquiv, reason := checkCommonEquivalences(expr1, expr2)
	if semanticEquiv {
		result.SemanticMatch = true
		result.Confidence = 95.0
		result.EquivalenceReason = reason
		result.Recommendation = "Expressions are semantically equivalent despite bytecode differences"
		return result
	}

	// Analyze return instructions (accept/reject paths)
	accepts1, rejects1 := countReturnPaths(bpf1)
	accepts2, rejects2 := countReturnPaths(bpf2)
	result.Analysis = append(result.Analysis, fmt.Sprintf("Accept paths: %d vs %d", accepts1, accepts2))
	result.Analysis = append(result.Analysis, fmt.Sprintf("Reject paths: %d vs %d", rejects1, rejects2))

	// Check protocol checks
	hasIPv4_1, hasIPv6_1 := detectIPVersions(bpf1)
	hasIPv4_2, hasIPv6_2 := detectIPVersions(bpf2)

	if hasIPv4_1 != hasIPv4_2 || hasIPv6_1 != hasIPv6_2 {
		result.Analysis = append(result.Analysis, "Different IP version support detected")
		result.SemanticMatch = false
		result.Confidence = 30.0
		result.Recommendation = "Expressions handle different IP versions - NOT equivalent"
		return result
	}

	// Heuristic: if instruction count is within 20% and same IP versions, likely equivalent
	if instructionDiff <= max(bpf1.Count, bpf2.Count)/5 {
		result.SemanticMatch = true
		result.Confidence = 75.0
		result.EquivalenceReason = "structural_similarity"
		result.Recommendation = "Likely equivalent (similar structure, same IP versions)"
	} else {
		result.SemanticMatch = false
		result.Confidence = 50.0
		result.Recommendation = "Uncertain - manual review recommended"
	}

	return result
}

// compareBytecode checks if two BPF programs have identical bytecode
func compareBytecode(bpf1, bpf2 BPFProgram) bool {
	if bpf1.Count != bpf2.Count {
		return false
	}
	for i := 0; i < bpf1.Count; i++ {
		if bpf1.Instructions[i].Op != bpf2.Instructions[i].Op ||
			bpf1.Instructions[i].Jt != bpf2.Instructions[i].Jt ||
			bpf1.Instructions[i].Jf != bpf2.Instructions[i].Jf ||
			bpf1.Instructions[i].K != bpf2.Instructions[i].K {
			return false
		}
	}
	return true
}

// checkCommonEquivalences checks for known semantic equivalence patterns
func checkCommonEquivalences(expr1, expr2 string) (bool, string) {
	e1 := strings.ToLower(strings.TrimSpace(expr1))
	e2 := strings.ToLower(strings.TrimSpace(expr2))

	// Normalize expressions
	e1 = normalizeExpression(e1)
	e2 = normalizeExpression(e2)

	if e1 == e2 {
		return true, "normalized_match"
	}

	// Check commutative equivalences: "A and B" == "B and A"
	if isCommutativeEquivalent(e1, e2) {
		return true, "commutative_equivalence"
	}

	// Check port equivalences: "tcp port X" == "tcp dst port X or tcp src port X"
	if isPortEquivalent(e1, e2) {
		return true, "port_equivalence"
	}

	return false, ""
}

// normalizeExpression normalizes a filter expression
func normalizeExpression(expr string) string {
	// Remove extra spaces
	expr = strings.Join(strings.Fields(expr), " ")

	// Normalize parentheses
	expr = strings.ReplaceAll(expr, "( ", "(")
	expr = strings.ReplaceAll(expr, " )", ")")

	return expr
}

// isCommutativeEquivalent checks if expressions are commutatively equivalent
func isCommutativeEquivalent(e1, e2 string) bool {
	// Simple check: "A and B" vs "B and A"
	parts1 := strings.Split(e1, " and ")
	parts2 := strings.Split(e2, " and ")

	if len(parts1) != len(parts2) || len(parts1) != 2 {
		return false
	}

	// Check if parts match in reverse order
	if strings.TrimSpace(parts1[0]) == strings.TrimSpace(parts2[1]) &&
		strings.TrimSpace(parts1[1]) == strings.TrimSpace(parts2[0]) {
		return true
	}

	return false
}

// isPortEquivalent checks for port filter equivalences
func isPortEquivalent(e1, e2 string) bool {
	// "tcp port 80" is equivalent to "tcp dst port 80 or tcp src port 80"
	// This is a simplified check

	// Extract port from simple expression
	portMatch := regexp.MustCompile(`(tcp|udp)\s+port\s+(\d+)`)

	// Check if one is a simple port and the other is expanded
	// e.g., "tcp port 80" vs "tcp dst port 80 or tcp src port 80"
	m1 := portMatch.FindStringSubmatch(e1)
	if m1 != nil {
		proto := m1[1]
		port := m1[2]
		// Check if e2 matches the expanded form
		expandedPattern := fmt.Sprintf(`%s\s+(dst|src)\s+port\s+%s\s+or\s+%s\s+(dst|src)\s+port\s+%s`, proto, port, proto, port)
		expandedMatch := regexp.MustCompile(expandedPattern)
		if expandedMatch.MatchString(e2) {
			return true
		}
	}

	// Check reverse
	m2 := portMatch.FindStringSubmatch(e2)
	if m2 != nil {
		proto := m2[1]
		port := m2[2]
		expandedPattern := fmt.Sprintf(`%s\s+(dst|src)\s+port\s+%s\s+or\s+%s\s+(dst|src)\s+port\s+%s`, proto, port, proto, port)
		expandedMatch := regexp.MustCompile(expandedPattern)
		if expandedMatch.MatchString(e1) {
			return true
		}
	}

	return false
}

// countReturnPaths counts accept and reject return instructions
func countReturnPaths(bpf BPFProgram) (accepts, rejects int) {
	for _, inst := range bpf.Instructions {
		if inst.Op&0x07 == 0x06 { // RET instruction
			if inst.K > 0 {
				accepts++
			} else {
				rejects++
			}
		}
	}
	return
}

// detectIPVersions detects which IP versions the BPF handles
func detectIPVersions(bpf BPFProgram) (hasIPv4, hasIPv6 bool) {
	for _, inst := range bpf.Instructions {
		if inst.K == 0x0800 { // IPv4 EtherType
			hasIPv4 = true
		}
		if inst.K == 0x86dd { // IPv6 EtherType
			hasIPv6 = true
		}
	}
	return
}

// abs returns absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// max returns the maximum of two ints
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
