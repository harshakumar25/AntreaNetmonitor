import { cn } from '@/lib/utils'

interface ConnectionsListProps {
  connections: Array<{
    id: string
    srcIP: string
    dstIP: string
    protocol: string
    state: string
    bytesReceived: number
    bytesSent: number
    latency: number
  }>
}

export default function ConnectionsList({ connections }: ConnectionsListProps) {
  const getStateColor = (state: string) => {
    const colors: Record<string, string> = {
      ESTABLISHED: 'bg-green-500/20 text-green-400',
      SYN_SENT: 'bg-yellow-500/20 text-yellow-400',
      SYN_RECV: 'bg-yellow-500/20 text-yellow-400',
      FIN_WAIT: 'bg-orange-500/20 text-orange-400',
      TIME_WAIT: 'bg-blue-500/20 text-blue-400',
      CLOSE_WAIT: 'bg-red-500/20 text-red-400',
    }
    return colors[state] || 'bg-gray-500/20 text-gray-400'
  }

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-dark-border flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Active Connections</h3>
        <span className="text-sm text-gray-400">{connections.length} active</span>
      </div>
      
      <div className="overflow-x-auto max-h-80 overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="bg-dark-border/50 sticky top-0">
            <tr>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Source</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Destination</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Protocol</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">State</th>
              <th className="px-4 py-3 text-left text-gray-400 font-medium">Latency</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-border">
            {connections.slice(0, 20).map((conn) => (
              <tr key={conn.id} className="hover:bg-dark-border/30 transition-colors">
                <td className="px-4 py-3 text-white font-mono text-xs">{conn.srcIP}</td>
                <td className="px-4 py-3 text-white font-mono text-xs">{conn.dstIP}</td>
                <td className="px-4 py-3 text-gray-300">{conn.protocol}</td>
                <td className="px-4 py-3">
                  <span className={cn('px-2 py-1 rounded text-xs font-medium', getStateColor(conn.state))}>
                    {conn.state}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-300">{conn.latency.toFixed(1)}ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
