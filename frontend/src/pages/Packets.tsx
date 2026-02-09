import { useState, useCallback, useRef, useEffect } from 'react'
import { Play, Pause, Trash2, Filter } from 'lucide-react'
import PacketTable from '@/components/PacketTable'
import { usePacketStream } from '@/hooks/useWebSocket'
import type { Packet } from '@/types'

export default function Packets() {
  const [packets, setPackets] = useState<Packet[]>([])
  const [isPaused, setIsPaused] = useState(false)
  const [filter, setFilter] = useState('')
  const [selectedProtocol, setSelectedProtocol] = useState<string>('all')
  const maxPackets = 500
  const isPausedRef = useRef(isPaused)

  useEffect(() => {
    isPausedRef.current = isPaused
  }, [isPaused])

  const handlePacket = useCallback((packet: Packet) => {
    if (isPausedRef.current) return
    
    setPackets(prev => {
      const updated = [packet, ...prev]
      return updated.slice(0, maxPackets)
    })
  }, [])

  const { isConnected } = usePacketStream(handlePacket)

  // Simulate packets when not connected
  useEffect(() => {
    if (isConnected) return

    const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP']
    const internalIPs = ['192.168.1.10', '192.168.1.20', '10.0.0.5', '172.16.0.100']
    const externalIPs = ['8.8.8.8', '142.250.190.46', '151.101.1.140', '1.1.1.1']

    const interval = setInterval(() => {
      if (isPausedRef.current) return

      const isOutbound = Math.random() > 0.5
      const packet: Packet = {
        id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        srcIP: isOutbound ? internalIPs[Math.floor(Math.random() * internalIPs.length)] : externalIPs[Math.floor(Math.random() * externalIPs.length)],
        dstIP: isOutbound ? externalIPs[Math.floor(Math.random() * externalIPs.length)] : internalIPs[Math.floor(Math.random() * internalIPs.length)],
        srcPort: isOutbound ? 30000 + Math.floor(Math.random() * 35000) : [80, 443, 53, 22][Math.floor(Math.random() * 4)],
        dstPort: isOutbound ? [80, 443, 53, 22][Math.floor(Math.random() * 4)] : 30000 + Math.floor(Math.random() * 35000),
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        length: Math.floor(Math.random() * 1400) + 100,
        ttl: 64 + Math.floor(Math.random() * 64),
        payloadSize: Math.floor(Math.random() * 1360) + 60,
        direction: isOutbound ? 'outbound' : 'inbound',
      }

      setPackets(prev => [packet, ...prev].slice(0, maxPackets))
    }, 50)

    return () => clearInterval(interval)
  }, [isConnected])

  const clearPackets = () => setPackets([])

  const filteredPackets = packets.filter(packet => {
    const matchesFilter = filter === '' || 
      packet.srcIP.includes(filter) || 
      packet.dstIP.includes(filter) ||
      packet.protocol.toLowerCase().includes(filter.toLowerCase())
    
    const matchesProtocol = selectedProtocol === 'all' || packet.protocol === selectedProtocol

    return matchesFilter && matchesProtocol
  })

  const protocols = ['all', 'TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'SSH', 'FTP']

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Live Packet Capture</h1>
          <p className="text-gray-400 mt-1">Real-time network packet inspection</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center px-3 py-1.5 rounded-full bg-dark-card border border-dark-border">
            <span className={`w-2 h-2 rounded-full mr-2 ${isConnected || !isPaused ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`} />
            <span className="text-sm text-gray-400">
              {isPaused ? 'Paused' : 'Capturing'}
            </span>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-4 bg-dark-card border border-dark-border rounded-xl p-4">
        {/* Play/Pause */}
        <button
          onClick={() => setIsPaused(!isPaused)}
          className={`flex items-center px-4 py-2 rounded-lg font-medium transition-colors ${
            isPaused 
              ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' 
              : 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30'
          }`}
        >
          {isPaused ? (
            <>
              <Play className="w-4 h-4 mr-2" />
              Resume
            </>
          ) : (
            <>
              <Pause className="w-4 h-4 mr-2" />
              Pause
            </>
          )}
        </button>

        {/* Clear */}
        <button
          onClick={clearPackets}
          className="flex items-center px-4 py-2 rounded-lg font-medium bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
        >
          <Trash2 className="w-4 h-4 mr-2" />
          Clear
        </button>

        {/* Filter Input */}
        <div className="relative flex-1 min-w-64">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Filter by IP or protocol..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-dark-bg border border-dark-border rounded-lg 
                       text-white placeholder-gray-500 focus:outline-none focus:border-primary-500"
          />
        </div>

        {/* Protocol Select */}
        <select
          value={selectedProtocol}
          onChange={(e) => setSelectedProtocol(e.target.value)}
          className="px-4 py-2 bg-dark-bg border border-dark-border rounded-lg text-white 
                     focus:outline-none focus:border-primary-500"
        >
          {protocols.map(p => (
            <option key={p} value={p}>
              {p === 'all' ? 'All Protocols' : p}
            </option>
          ))}
        </select>

        {/* Stats */}
        <div className="text-sm text-gray-400 ml-auto">
          <span className="font-mono">{filteredPackets.length}</span> packets
          {filter && <span className="ml-2">(filtered from {packets.length})</span>}
        </div>
      </div>

      {/* Packet Table */}
      <PacketTable packets={filteredPackets} maxRows={100} />
    </div>
  )
}
