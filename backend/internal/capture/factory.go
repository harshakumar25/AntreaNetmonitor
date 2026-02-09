package capture

import (
	"log"
	"network-monitor/pkg/models"
	"os"
)

// CaptureMode defines the capture engine mode
type CaptureMode string

const (
	ModeMock   CaptureMode = "mock"
	ModeAntrea CaptureMode = "antrea"
)

// CaptureInterface defines the common interface for capture engines
type CaptureInterface interface {
	Start()
	Stop()
	GetPacketChannel() <-chan Packet
	GetStatsChannel() <-chan TrafficStats
	GetAlertsChannel() <-chan Alert
	GetConnections() []Connection
	GetCurrentStats() TrafficStats
}

// Import models
type Packet = models.Packet
type TrafficStats = models.TrafficStats
type Alert = models.Alert
type Connection = models.Connection

// NewCaptureEngineWithMode creates the appropriate capture engine based on mode
func NewCaptureEngineWithMode(mode CaptureMode) interface{} {
	switch mode {
	case ModeAntrea:
		antreaAddr := os.Getenv("ANTREA_AGENT_ADDR")
		if antreaAddr == "" {
			antreaAddr = "http://localhost:10350"
		}
		kubeconfig := os.Getenv("KUBECONFIG")
		log.Println("🔧 Using REAL Antrea packet capture mode")
		return NewAntreaCaptureEngine(antreaAddr, kubeconfig)

	default:
		log.Println("🎭 Using MOCK packet capture mode (simulated data)")
		return NewCaptureEngine()
	}
}

// GetCaptureMode returns the configured capture mode from environment
func GetCaptureMode() CaptureMode {
	mode := os.Getenv("CAPTURE_MODE")
	switch mode {
	case "antrea", "real":
		return ModeAntrea
	default:
		return ModeMock
	}
}
