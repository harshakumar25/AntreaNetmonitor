package models

import "time"

// Packet represents a captured network packet
type Packet struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"srcIP"`
	DestIP      string    `json:"dstIP"`
	SourcePort  int       `json:"srcPort"`
	DestPort    int       `json:"dstPort"`
	Protocol    string    `json:"protocol"`
	Length      int       `json:"length"`
	TTL         int       `json:"ttl"`
	Flags       []string  `json:"flags,omitempty"`
	PayloadSize int       `json:"payloadSize"`
	Direction   string    `json:"direction"` // "inbound" or "outbound"
}

// Connection represents an active network connection
type Connection struct {
	ID            string    `json:"id"`
	SourceIP      string    `json:"srcIP"`
	DestIP        string    `json:"dstIP"`
	SourcePort    int       `json:"srcPort"`
	DestPort      int       `json:"dstPort"`
	Protocol      string    `json:"protocol"`
	State         string    `json:"state"`
	BytesSent     int64     `json:"bytesSent"`
	BytesReceived int64     `json:"bytesReceived"`
	PacketCount   int64     `json:"packetCount"`
	StartTime     time.Time `json:"startTime"`
	LastActivity  time.Time `json:"lastActivity"`
	Latency       float64   `json:"latency"` // in milliseconds
}

// TrafficStats represents aggregated traffic statistics
type TrafficStats struct {
	Timestamp         time.Time          `json:"timestamp"`
	TotalBytes        int64              `json:"totalBytes"`
	TotalPackets      int64              `json:"totalPackets"`
	BytesPerSecond    float64            `json:"bytesPerSecond"`
	PacketsPerSecond  float64            `json:"packetsPerSecond"`
	ActiveConnections int                `json:"activeConnections"`
	ProtocolStats     map[string]int64   `json:"protocolStats"`
	TopSourceIPs      []IPStats          `json:"topSourceIPs"`
	TopDestIPs        []IPStats          `json:"topDestIPs"`
	BandwidthIn       float64            `json:"bandwidthIn"`
	BandwidthOut      float64            `json:"bandwidthOut"`
	ErrorRate         float64            `json:"errorRate"`
	LatencyAvg        float64            `json:"latencyAvg"`
	LatencyP95        float64            `json:"latencyP95"`
	LatencyP99        float64            `json:"latencyP99"`
}

// IPStats represents traffic statistics for a specific IP
type IPStats struct {
	IP          string  `json:"ip"`
	Bytes       int64   `json:"bytes"`
	Packets     int64   `json:"packets"`
	Connections int     `json:"connections"`
	Location    string  `json:"location,omitempty"`
	Country     string  `json:"country,omitempty"`
}

// Alert represents a system alert
type Alert struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "warning", "critical", "info"
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
	Resolved  bool      `json:"resolved"`
}

// WebSocketMessage represents a message sent over WebSocket
type WebSocketMessage struct {
	Type      string      `json:"type"` // "packet", "stats", "alert", "connection"
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Filter represents a packet filter
type Filter struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	SourceIPs  []string `json:"sourceIPs,omitempty"`
	DestIPs    []string `json:"destIPs,omitempty"`
	Protocols  []string `json:"protocols,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
	MinSize    int      `json:"minSize,omitempty"`
	MaxSize    int      `json:"maxSize,omitempty"`
	Active     bool     `json:"active"`
}

// HistoricalQuery represents parameters for querying historical data
type HistoricalQuery struct {
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	Granularity string    `json:"granularity"` // "1m", "5m", "1h", "1d"
	Protocols   []string  `json:"protocols,omitempty"`
}

// NetworkTopology represents the network topology data
type NetworkTopology struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}

// TopologyNode represents a node in the network topology
type TopologyNode struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Type     string `json:"type"` // "server", "client", "router", "external"
	IP       string `json:"ip"`
	Traffic  int64  `json:"traffic"`
	Status   string `json:"status"` // "active", "idle", "warning"
}

// TopologyEdge represents a connection between nodes
type TopologyEdge struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Weight    int64  `json:"weight"`
	Protocol  string `json:"protocol"`
	Bandwidth float64 `json:"bandwidth"`
}
