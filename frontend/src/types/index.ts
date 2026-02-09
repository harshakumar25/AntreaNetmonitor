// Packet types
export interface Packet {
  id: string
  timestamp: string
  srcIP: string
  dstIP: string
  srcPort: number
  dstPort: number
  protocol: string
  length: number
  ttl: number
  flags?: string[]
  payloadSize: number
  direction: 'inbound' | 'outbound'
}

// Connection types
export interface Connection {
  id: string
  srcIP: string
  dstIP: string
  srcPort: number
  dstPort: number
  protocol: string
  state: string
  bytesSent: number
  bytesReceived: number
  packetCount: number
  startTime: string
  lastActivity: string
  latency: number
}

// Statistics types
export interface TrafficStats {
  timestamp: string
  totalBytes: number
  totalPackets: number
  bytesPerSecond: number
  packetsPerSecond: number
  activeConnections: number
  protocolStats: Record<string, number>
  topSourceIPs: IPStats[]
  topDestIPs: IPStats[]
  bandwidthIn: number
  bandwidthOut: number
  errorRate: number
  latencyAvg: number
  latencyP95: number
  latencyP99: number
}

export interface IPStats {
  ip: string
  bytes: number
  packets: number
  connections: number
  location?: string
  country?: string
}

// Alert types
export interface Alert {
  id: string
  type: 'warning' | 'critical' | 'info'
  title: string
  message: string
  source: string
  timestamp: string
  resolved: boolean
}

// WebSocket message types
export interface WebSocketMessage {
  type: 'packet' | 'stats' | 'alert'
  timestamp: string
  data: Packet | TrafficStats | Alert
}

// Network topology types
export interface TopologyNode {
  id: string
  label: string
  type: 'server' | 'client' | 'router' | 'external'
  ip: string
  traffic: number
  status: 'active' | 'idle' | 'warning'
}

export interface TopologyEdge {
  source: string
  target: string
  weight: number
  protocol: string
  bandwidth: number
}

export interface NetworkTopology {
  nodes: TopologyNode[]
  edges: TopologyEdge[]
}

// Filter types
export interface Filter {
  id: string
  name: string
  sourceIPs?: string[]
  destIPs?: string[]
  protocols?: string[]
  ports?: number[]
  minSize?: number
  maxSize?: number
  active: boolean
}
