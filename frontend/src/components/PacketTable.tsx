import { useMemo } from 'react'
import type { Packet } from '@/types'
import { cn, formatBytes, getProtocolColor } from '@/lib/utils'

interface PacketTableProps {
  packets: Packet[]
  maxRows?: number
}

export default function PacketTable({ packets, maxRows = 50 }: PacketTableProps) {
  const displayPackets = useMemo(() => 
    packets.slice(0, maxRows),
    [packets, maxRows]
  )

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-dark-border flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Live Packets</h3>
        <div className="flex items-center text-sm text-gray-400">
          <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse mr-2" />
          {packets.length} packets captured
        </div>
      </div>
      
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-dark-border/50">
            <tr>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Time</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Source</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Destination</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Protocol</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Size</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Direction</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-border">
            {displayPackets.map((packet) => (
              <tr 
                key={packet.id}
                className="hover:bg-dark-border/30 transition-colors animate-fade-in"
              >
                <td className="px-4 py-3 text-gray-300 font-mono text-xs">
                  {new Date(packet.timestamp).toLocaleTimeString()}
                </td>
                <td className="px-4 py-3 text-white font-mono">
                  {packet.srcIP}:{packet.srcPort}
                </td>
                <td className="px-4 py-3 text-white font-mono">
                  {packet.dstIP}:{packet.dstPort}
                </td>
                <td className="px-4 py-3">
                  <span 
                    className="px-2 py-1 rounded text-xs font-medium"
                    style={{ 
                      backgroundColor: `${getProtocolColor(packet.protocol)}20`,
                      color: getProtocolColor(packet.protocol)
                    }}
                  >
                    {packet.protocol}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-300">
                  {formatBytes(packet.length)}
                </td>
                <td className="px-4 py-3">
                  <span className={cn(
                    'px-2 py-1 rounded text-xs font-medium',
                    packet.direction === 'inbound' 
                      ? 'bg-blue-500/20 text-blue-400' 
                      : 'bg-green-500/20 text-green-400'
                  )}>
                    {packet.direction === 'inbound' ? '↓ IN' : '↑ OUT'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {packets.length > maxRows && (
        <div className="px-6 py-3 bg-dark-border/30 text-center text-sm text-gray-400">
          Showing {maxRows} of {packets.length} packets
        </div>
      )}
    </div>
  )
}
