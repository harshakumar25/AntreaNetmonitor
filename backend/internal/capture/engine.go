package capture

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/google/uuid"
	"network-monitor/pkg/models"
)

// CaptureEngine simulates network packet capture
type CaptureEngine struct {
	packets     chan models.Packet
	stats       chan models.TrafficStats
	alerts      chan models.Alert
	connections map[string]*models.Connection
	mu          sync.RWMutex
	running     bool
	stopChan    chan struct{}

	// Metrics
	totalBytes     int64
	totalPackets   int64
	protocolCounts map[string]int64
	sourceIPCounts map[string]int64
	destIPCounts   map[string]int64
}

// Common IP addresses for simulation
var (
	internalIPs = []string{
		"192.168.1.10", "192.168.1.20", "192.168.1.30",
		"10.0.0.5", "10.0.0.15", "10.0.0.25",
		"172.16.0.100", "172.16.0.200",
	}
	externalIPs = []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1",
		"142.250.190.46", "151.101.1.140", "104.244.42.1",
		"13.107.42.14", "52.96.166.242", "20.190.151.68",
		"199.232.69.194", "185.199.108.153",
	}
	protocols  = []string{"TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "SSH", "FTP"}
	tcpFlags   = []string{"SYN", "ACK", "FIN", "RST", "PSH", "URG"}
	connStates = []string{"ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "TIME_WAIT", "CLOSE_WAIT"}
)

// NewCaptureEngine creates a new capture engine
func NewCaptureEngine() *CaptureEngine {
	return &CaptureEngine{
		packets:        make(chan models.Packet, 1000),
		stats:          make(chan models.TrafficStats, 100),
		alerts:         make(chan models.Alert, 100),
		connections:    make(map[string]*models.Connection),
		stopChan:       make(chan struct{}),
		protocolCounts: make(map[string]int64),
		sourceIPCounts: make(map[string]int64),
		destIPCounts:   make(map[string]int64),
	}
}

// Start begins packet capture simulation
func (e *CaptureEngine) Start() {
	e.running = true

	// Packet generation goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond) // ~100 packets/sec
		defer ticker.Stop()

		for {
			select {
			case <-e.stopChan:
				return
			case <-ticker.C:
				packet := e.generatePacket()
				e.updateMetrics(packet)

				select {
				case e.packets <- packet:
				default:
					// Channel full, drop packet
				}
			}
		}
	}()

	// Stats aggregation goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-e.stopChan:
				return
			case <-ticker.C:
				stats := e.aggregateStats()
				select {
				case e.stats <- stats:
				default:
				}
			}
		}
	}()

	// Alert generation goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-e.stopChan:
				return
			case <-ticker.C:
				if rand.Float32() < 0.2 { // 20% chance of alert
					alert := e.generateAlert()
					select {
					case e.alerts <- alert:
					default:
					}
				}
			}
		}
	}()
}

// Stop halts the capture engine
func (e *CaptureEngine) Stop() {
	e.running = false
	close(e.stopChan)
}

// GetPacketChannel returns the packet channel
func (e *CaptureEngine) GetPacketChannel() <-chan models.Packet {
	return e.packets
}

// GetStatsChannel returns the stats channel
func (e *CaptureEngine) GetStatsChannel() <-chan models.TrafficStats {
	return e.stats
}

// GetAlertsChannel returns the alerts channel
func (e *CaptureEngine) GetAlertsChannel() <-chan models.Alert {
	return e.alerts
}

// GetConnections returns current active connections
func (e *CaptureEngine) GetConnections() []models.Connection {
	e.mu.RLock()
	defer e.mu.RUnlock()

	conns := make([]models.Connection, 0, len(e.connections))
	for _, conn := range e.connections {
		conns = append(conns, *conn)
	}
	return conns
}

// GetCurrentStats returns the current statistics snapshot
func (e *CaptureEngine) GetCurrentStats() models.TrafficStats {
	return e.aggregateStats()
}

func (e *CaptureEngine) generatePacket() models.Packet {
	isOutbound := rand.Float32() > 0.5
	protocol := protocols[rand.Intn(len(protocols))]

	var srcIP, dstIP string
	var srcPort, dstPort int

	if isOutbound {
		srcIP = internalIPs[rand.Intn(len(internalIPs))]
		dstIP = externalIPs[rand.Intn(len(externalIPs))]
		srcPort = 30000 + rand.Intn(35000)
		dstPort = e.getPortForProtocol(protocol)
	} else {
		srcIP = externalIPs[rand.Intn(len(externalIPs))]
		dstIP = internalIPs[rand.Intn(len(internalIPs))]
		srcPort = e.getPortForProtocol(protocol)
		dstPort = 30000 + rand.Intn(35000)
	}

	// Generate realistic packet size based on protocol
	length := e.getPacketSize(protocol)

	direction := "outbound"
	if !isOutbound {
		direction = "inbound"
	}

	packet := models.Packet{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		SourceIP:    srcIP,
		DestIP:      dstIP,
		SourcePort:  srcPort,
		DestPort:    dstPort,
		Protocol:    protocol,
		Length:      length,
		TTL:         64 + rand.Intn(64),
		PayloadSize: length - 40, // Subtract header size
		Direction:   direction,
	}

	// Add TCP flags if TCP protocol
	if protocol == "TCP" {
		numFlags := 1 + rand.Intn(3)
		packet.Flags = make([]string, numFlags)
		for i := 0; i < numFlags; i++ {
			packet.Flags[i] = tcpFlags[rand.Intn(len(tcpFlags))]
		}
	}

	// Update or create connection
	e.updateConnection(packet)

	return packet
}

func (e *CaptureEngine) getPortForProtocol(protocol string) int {
	switch protocol {
	case "HTTP":
		return 80
	case "HTTPS":
		return 443
	case "DNS":
		return 53
	case "SSH":
		return 22
	case "FTP":
		return 21
	default:
		return rand.Intn(65535)
	}
}

func (e *CaptureEngine) getPacketSize(protocol string) int {
	switch protocol {
	case "DNS":
		return 50 + rand.Intn(200)
	case "ICMP":
		return 64 + rand.Intn(100)
	case "HTTP", "HTTPS":
		return 200 + rand.Intn(1300)
	default:
		return 100 + rand.Intn(1400)
	}
}

func (e *CaptureEngine) updateMetrics(packet models.Packet) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.totalBytes += int64(packet.Length)
	e.totalPackets++
	e.protocolCounts[packet.Protocol]++
	e.sourceIPCounts[packet.SourceIP]++
	e.destIPCounts[packet.DestIP]++
}

func (e *CaptureEngine) updateConnection(packet models.Packet) {
	e.mu.Lock()
	defer e.mu.Unlock()

	connID := fmt.Sprintf("%s:%d-%s:%d-%s",
		packet.SourceIP, packet.SourcePort,
		packet.DestIP, packet.DestPort,
		packet.Protocol)

	if conn, exists := e.connections[connID]; exists {
		conn.PacketCount++
		conn.LastActivity = time.Now()
		if packet.Direction == "outbound" {
			conn.BytesSent += int64(packet.Length)
		} else {
			conn.BytesReceived += int64(packet.Length)
		}
		conn.Latency = 5 + rand.Float64()*95 // 5-100ms
	} else {
		e.connections[connID] = &models.Connection{
			ID:            connID,
			SourceIP:      packet.SourceIP,
			DestIP:        packet.DestIP,
			SourcePort:    packet.SourcePort,
			DestPort:      packet.DestPort,
			Protocol:      packet.Protocol,
			State:         connStates[rand.Intn(len(connStates))],
			PacketCount:   1,
			StartTime:     time.Now(),
			LastActivity:  time.Now(),
			Latency:       5 + rand.Float64()*95,
		}
	}

	// Cleanup old connections
	if len(e.connections) > 1000 {
		for id, conn := range e.connections {
			if time.Since(conn.LastActivity) > 30*time.Second {
				delete(e.connections, id)
			}
		}
	}
}

func (e *CaptureEngine) aggregateStats() models.TrafficStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Calculate top IPs
	topSources := e.getTopIPs(e.sourceIPCounts, 5)
	topDests := e.getTopIPs(e.destIPCounts, 5)

	// Copy protocol stats
	protoStats := make(map[string]int64)
	for k, v := range e.protocolCounts {
		protoStats[k] = v
	}

	// Calculate bandwidth with some variance
	bandwidthIn := float64(e.totalBytes) * 0.4 * (0.8 + rand.Float64()*0.4)
	bandwidthOut := float64(e.totalBytes) * 0.6 * (0.8 + rand.Float64()*0.4)

	return models.TrafficStats{
		Timestamp:         time.Now(),
		TotalBytes:        e.totalBytes,
		TotalPackets:      e.totalPackets,
		BytesPerSecond:    float64(e.totalBytes) / 100 * (0.8 + rand.Float64()*0.4),
		PacketsPerSecond:  float64(e.totalPackets) / 100 * (0.8 + rand.Float64()*0.4),
		ActiveConnections: len(e.connections),
		ProtocolStats:     protoStats,
		TopSourceIPs:      topSources,
		TopDestIPs:        topDests,
		BandwidthIn:       bandwidthIn,
		BandwidthOut:      bandwidthOut,
		ErrorRate:         rand.Float64() * 0.5,
		LatencyAvg:        20 + rand.Float64()*30,
		LatencyP95:        50 + rand.Float64()*50,
		LatencyP99:        80 + rand.Float64()*70,
	}
}

func (e *CaptureEngine) getTopIPs(counts map[string]int64, limit int) []models.IPStats {
	type ipCount struct {
		ip    string
		count int64
	}

	var sorted []ipCount
	for ip, count := range counts {
		sorted = append(sorted, ipCount{ip, count})
	}

	// Simple bubble sort for small list
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	result := make([]models.IPStats, 0, limit)
	for i := 0; i < len(sorted) && i < limit; i++ {
		result = append(result, models.IPStats{
			IP:      sorted[i].ip,
			Packets: sorted[i].count,
			Bytes:   sorted[i].count * 500, // Estimate
		})
	}

	return result
}

func (e *CaptureEngine) generateAlert() models.Alert {
	alertTypes := []struct {
		alertType string
		title     string
		message   string
	}{
		{"warning", "High Bandwidth Usage", "Bandwidth usage exceeded 80% threshold"},
		{"critical", "Connection Spike Detected", "Unusual spike in connection attempts detected"},
		{"info", "New Device Detected", "A new device has joined the network"},
		{"warning", "Latency Increase", "Network latency has increased above normal levels"},
		{"critical", "Potential DDoS Attack", "Suspicious traffic pattern detected from multiple sources"},
		{"info", "Scheduled Maintenance", "Network maintenance window approaching"},
	}

	alert := alertTypes[rand.Intn(len(alertTypes))]

	return models.Alert{
		ID:        uuid.New().String(),
		Type:      alert.alertType,
		Title:     alert.title,
		Message:   alert.message,
		Source:    externalIPs[rand.Intn(len(externalIPs))],
		Timestamp: time.Now(),
		Resolved:  false,
	}
}
