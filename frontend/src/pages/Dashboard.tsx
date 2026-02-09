import { useState, useCallback, useEffect } from 'react'
import { Activity, Zap, Users, TrendingUp } from 'lucide-react'
import StatCard from '@/components/StatCard'
import { ThroughputChart, PacketRateChart, LatencyChart } from '@/components/Charts'
import ProtocolChart from '@/components/ProtocolChart'
import TopTalkers from '@/components/TopTalkers'
import ConnectionsList from '@/components/ConnectionsList'
import AlertList from '@/components/AlertList'
import { useStatsStream } from '@/hooks/useWebSocket'
import { formatBytes, formatNumber } from '@/lib/utils'
import type { TrafficStats, Alert } from '@/types'

// Generate initial mock data
const generateMockData = () => {
  const now = new Date()
  return Array.from({ length: 30 }, (_, i) => {
    const time = new Date(now.getTime() - (29 - i) * 2000)
    return {
      time: time.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      bytesIn: Math.random() * 500000 + 100000,
      bytesOut: Math.random() * 400000 + 80000,
      packets: Math.random() * 1000 + 500,
      avg: Math.random() * 30 + 20,
      p95: Math.random() * 40 + 50,
      p99: Math.random() * 50 + 80,
    }
  })
}

export default function Dashboard() {
  const [stats, setStats] = useState<TrafficStats | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [chartData, setChartData] = useState(generateMockData())
  const [connections, setConnections] = useState<any[]>([])

  // Handle incoming stats from WebSocket
  const handleStats = useCallback((newStats: TrafficStats) => {
    setStats(newStats)
    
    // Update chart data
    setChartData(prev => {
      const time = new Date().toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
      })
      const newPoint = {
        time,
        bytesIn: newStats.bandwidthIn,
        bytesOut: newStats.bandwidthOut,
        packets: newStats.packetsPerSecond,
        avg: newStats.latencyAvg,
        p95: newStats.latencyP95,
        p99: newStats.latencyP99,
      }
      return [...prev.slice(1), newPoint]
    })
  }, [])

  const handleAlert = useCallback((alert: Alert) => {
    setAlerts(prev => [alert, ...prev].slice(0, 20))
  }, [])

  const { isConnected } = useStatsStream(handleStats, handleAlert)

  // Fetch initial data and connections
  useEffect(() => {
    fetch('/api/v1/stats/live')
      .then(res => res.json())
      .then(setStats)
      .catch(console.error)

    fetch('/api/v1/connections')
      .then(res => res.json())
      .then(data => setConnections(data.connections || []))
      .catch(console.error)

    fetch('/api/v1/alerts')
      .then(res => res.json())
      .then(data => setAlerts(data.alerts || []))
      .catch(console.error)
  }, [])

  // Simulate data updates when not connected to WebSocket
  useEffect(() => {
    if (isConnected) return

    const interval = setInterval(() => {
      setChartData(prev => {
        const time = new Date().toLocaleTimeString('en-US', { 
          hour12: false, 
          hour: '2-digit', 
          minute: '2-digit', 
          second: '2-digit' 
        })
        const newPoint = {
          time,
          bytesIn: Math.random() * 500000 + 100000,
          bytesOut: Math.random() * 400000 + 80000,
          packets: Math.random() * 1000 + 500,
          avg: Math.random() * 30 + 20,
          p95: Math.random() * 40 + 50,
          p99: Math.random() * 50 + 80,
        }
        return [...prev.slice(1), newPoint]
      })

      // Update mock stats
      setStats(prev => ({
        timestamp: new Date().toISOString(),
        totalBytes: (prev?.totalBytes || 0) + Math.floor(Math.random() * 10000),
        totalPackets: (prev?.totalPackets || 0) + Math.floor(Math.random() * 100),
        bytesPerSecond: Math.random() * 500000 + 100000,
        packetsPerSecond: Math.random() * 1000 + 500,
        activeConnections: Math.floor(Math.random() * 100) + 50,
        protocolStats: {
          TCP: Math.floor(Math.random() * 5000) + 2000,
          UDP: Math.floor(Math.random() * 3000) + 1000,
          HTTP: Math.floor(Math.random() * 2000) + 500,
          HTTPS: Math.floor(Math.random() * 4000) + 1500,
          DNS: Math.floor(Math.random() * 1000) + 200,
          ICMP: Math.floor(Math.random() * 500) + 100,
        },
        topSourceIPs: [
          { ip: '192.168.1.10', bytes: Math.floor(Math.random() * 100000), packets: 500, connections: 10 },
          { ip: '192.168.1.20', bytes: Math.floor(Math.random() * 80000), packets: 400, connections: 8 },
          { ip: '10.0.0.5', bytes: Math.floor(Math.random() * 60000), packets: 300, connections: 6 },
          { ip: '172.16.0.100', bytes: Math.floor(Math.random() * 40000), packets: 200, connections: 4 },
          { ip: '192.168.1.30', bytes: Math.floor(Math.random() * 20000), packets: 100, connections: 2 },
        ],
        topDestIPs: [
          { ip: '8.8.8.8', bytes: Math.floor(Math.random() * 90000), packets: 450, connections: 9 },
          { ip: '142.250.190.46', bytes: Math.floor(Math.random() * 70000), packets: 350, connections: 7 },
          { ip: '151.101.1.140', bytes: Math.floor(Math.random() * 50000), packets: 250, connections: 5 },
          { ip: '104.244.42.1', bytes: Math.floor(Math.random() * 30000), packets: 150, connections: 3 },
          { ip: '1.1.1.1', bytes: Math.floor(Math.random() * 10000), packets: 50, connections: 1 },
        ],
        bandwidthIn: Math.random() * 500000 + 100000,
        bandwidthOut: Math.random() * 400000 + 80000,
        errorRate: Math.random() * 0.5,
        latencyAvg: Math.random() * 30 + 20,
        latencyP95: Math.random() * 40 + 50,
        latencyP99: Math.random() * 50 + 80,
      }))

      // Update mock connections
      setConnections([
        { id: '1', srcIP: '192.168.1.10', dstIP: '8.8.8.8', protocol: 'TCP', state: 'ESTABLISHED', bytesReceived: 50000, bytesSent: 30000, latency: 25 },
        { id: '2', srcIP: '192.168.1.20', dstIP: '142.250.190.46', protocol: 'HTTPS', state: 'ESTABLISHED', bytesReceived: 40000, bytesSent: 20000, latency: 35 },
        { id: '3', srcIP: '10.0.0.5', dstIP: '151.101.1.140', protocol: 'TCP', state: 'SYN_SENT', bytesReceived: 0, bytesSent: 1000, latency: 15 },
        { id: '4', srcIP: '172.16.0.100', dstIP: '1.1.1.1', protocol: 'DNS', state: 'ESTABLISHED', bytesReceived: 500, bytesSent: 200, latency: 10 },
        { id: '5', srcIP: '192.168.1.30', dstIP: '104.244.42.1', protocol: 'TCP', state: 'FIN_WAIT', bytesReceived: 60000, bytesSent: 35000, latency: 45 },
      ])
    }, 2000)

    return () => clearInterval(interval)
  }, [isConnected])

  const handleResolveAlert = (id: string) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, resolved: true } : a))
  }

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Bandwidth In"
          value={formatBytes(stats?.bandwidthIn || 0) + '/s'}
          change="+12.5%"
          changeType="positive"
          icon={<TrendingUp className="w-6 h-6" />}
        />
        <StatCard
          title="Bandwidth Out"
          value={formatBytes(stats?.bandwidthOut || 0) + '/s'}
          change="+8.3%"
          changeType="positive"
          icon={<Activity className="w-6 h-6" />}
        />
        <StatCard
          title="Packets/sec"
          value={formatNumber(stats?.packetsPerSecond || 0)}
          change="-2.1%"
          changeType="negative"
          icon={<Zap className="w-6 h-6" />}
        />
        <StatCard
          title="Active Connections"
          value={stats?.activeConnections || 0}
          change="+5"
          changeType="neutral"
          icon={<Users className="w-6 h-6" />}
        />
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ThroughputChart data={chartData} />
        <PacketRateChart data={chartData} />
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <ProtocolChart data={stats?.protocolStats || {}} />
        <TopTalkers 
          title="Top Sources" 
          data={stats?.topSourceIPs || []} 
          type="source"
        />
        <TopTalkers 
          title="Top Destinations" 
          data={stats?.topDestIPs || []} 
          type="destination"
        />
      </div>

      {/* Connections and Latency */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <LatencyChart data={chartData} />
        <ConnectionsList connections={connections} />
      </div>

      {/* Alerts */}
      <AlertList alerts={alerts} onResolve={handleResolveAlert} />
    </div>
  )
}
