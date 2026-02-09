import { useEffect, useState } from 'react'
import type { NetworkTopology, TopologyNode } from '@/types'
import { cn } from '@/lib/utils'

const fallbackTopology: NetworkTopology = {
  nodes: [
    { id: 'router-1', label: 'Main Router', type: 'router', ip: '192.168.1.1', status: 'active', traffic: 1500000 },
    { id: 'server-1', label: 'Web Server', type: 'server', ip: '192.168.1.10', status: 'active', traffic: 800000 },
    { id: 'server-2', label: 'DB Server', type: 'server', ip: '192.168.1.20', status: 'active', traffic: 500000 },
    { id: 'server-3', label: 'API Server', type: 'server', ip: '192.168.1.30', status: 'warning', traffic: 1200000 },
    { id: 'client-1', label: 'Workstation 1', type: 'client', ip: '192.168.1.100', status: 'active', traffic: 100000 },
    { id: 'client-2', label: 'Workstation 2', type: 'client', ip: '192.168.1.101', status: 'idle', traffic: 50000 },
    { id: 'external-1', label: 'CDN', type: 'external', ip: '142.250.190.46', status: 'active', traffic: 2000000 },
    { id: 'external-2', label: 'DNS', type: 'external', ip: '8.8.8.8', status: 'active', traffic: 100000 },
  ],
  edges: [
    { source: 'router-1', target: 'server-1', weight: 800000, protocol: 'TCP', bandwidth: 1000 },
    { source: 'router-1', target: 'server-2', weight: 500000, protocol: 'TCP', bandwidth: 500 },
    { source: 'router-1', target: 'server-3', weight: 1200000, protocol: 'TCP', bandwidth: 1200 },
    { source: 'router-1', target: 'client-1', weight: 100000, protocol: 'TCP', bandwidth: 100 },
    { source: 'router-1', target: 'client-2', weight: 50000, protocol: 'TCP', bandwidth: 50 },
    { source: 'router-1', target: 'external-1', weight: 2000000, protocol: 'HTTPS', bandwidth: 2000 },
    { source: 'router-1', target: 'external-2', weight: 100000, protocol: 'DNS', bandwidth: 100 },
  ],
}

export default function Topology() {
  const [topology, setTopology] = useState<NetworkTopology | null>(null)
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    const timeoutId = window.setTimeout(() => controller.abort(), 5000)

    fetch('/api/v1/topology', { signal: controller.signal })
      .then(res => {
        if (!res.ok) {
          throw new Error(`Topology request failed: ${res.status}`)
        }
        return res.json()
      })
      .then(setTopology)
      .catch(() => setTopology(fallbackTopology))
      .finally(() => window.clearTimeout(timeoutId))

    return () => controller.abort()
  }, [])

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'router': return '🌐'
      case 'server': return '🖥️'
      case 'client': return '💻'
      case 'external': return '☁️'
      default: return '📦'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'border-green-500 shadow-green-500/20'
      case 'warning': return 'border-yellow-500 shadow-yellow-500/20'
      case 'idle': return 'border-gray-500 shadow-gray-500/20'
      default: return 'border-gray-500'
    }
  }

  const formatTraffic = (bytes: number) => {
    if (bytes >= 1000000) return `${(bytes / 1000000).toFixed(1)}MB`
    if (bytes >= 1000) return `${(bytes / 1000).toFixed(1)}KB`
    return `${bytes}B`
  }

  // Simple circular layout
  const getNodePosition = (index: number, total: number, centerNode: boolean) => {
    if (centerNode && index === 0) {
      return { x: 400, y: 300 }
    }
    const adjustedIndex = centerNode ? index - 1 : index
    const adjustedTotal = centerNode ? total - 1 : total
    const angle = (adjustedIndex / adjustedTotal) * 2 * Math.PI - Math.PI / 2
    const radius = 200
    return {
      x: 400 + radius * Math.cos(angle),
      y: 300 + radius * Math.sin(angle)
    }
  }

  if (!topology) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-gray-400">Loading topology...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Network Topology</h1>
        <p className="text-gray-400 mt-1">Visual representation of network infrastructure</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Topology Visualization */}
        <div className="lg:col-span-2 bg-dark-card border border-dark-border rounded-xl p-6">
          <div className="relative w-full h-[600px] bg-dark-bg/50 rounded-lg overflow-hidden">
            <svg className="w-full h-full">
              {/* Connection Lines */}
              {topology.edges.map((edge, i) => {
                const sourceIndex = topology.nodes.findIndex(n => n.id === edge.source)
                const targetIndex = topology.nodes.findIndex(n => n.id === edge.target)
                const sourcePos = getNodePosition(sourceIndex, topology.nodes.length, true)
                const targetPos = getNodePosition(targetIndex, topology.nodes.length, true)
                
                return (
                  <line
                    key={i}
                    x1={sourcePos.x}
                    y1={sourcePos.y}
                    x2={targetPos.x}
                    y2={targetPos.y}
                    stroke="#334155"
                    strokeWidth={Math.max(1, edge.bandwidth / 500)}
                    strokeOpacity={0.6}
                    className="transition-all duration-300"
                  />
                )
              })}
            </svg>

            {/* Node Elements */}
            {topology.nodes.map((node, index) => {
              const pos = getNodePosition(index, topology.nodes.length, true)
              const isSelected = selectedNode?.id === node.id

              return (
                <div
                  key={node.id}
                  className={cn(
                    'absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all duration-300',
                    isSelected && 'scale-110 z-10'
                  )}
                  style={{ left: pos.x, top: pos.y }}
                  onClick={() => setSelectedNode(node)}
                >
                  <div className={cn(
                    'w-16 h-16 rounded-xl bg-dark-card border-2 flex items-center justify-center text-2xl shadow-lg transition-all',
                    getStatusColor(node.status),
                    isSelected && 'ring-2 ring-primary-500 ring-offset-2 ring-offset-dark-bg'
                  )}>
                    {getNodeIcon(node.type)}
                  </div>
                  <div className="absolute -bottom-6 left-1/2 -translate-x-1/2 whitespace-nowrap">
                    <span className="text-xs text-gray-400">{node.label}</span>
                  </div>
                </div>
              )
            })}

            {/* Legend */}
            <div className="absolute bottom-4 left-4 bg-dark-card/90 border border-dark-border rounded-lg p-3 text-xs">
              <div className="font-medium text-white mb-2">Legend</div>
              <div className="space-y-1 text-gray-400">
                <div className="flex items-center"><span className="mr-2">🌐</span> Router</div>
                <div className="flex items-center"><span className="mr-2">🖥️</span> Server</div>
                <div className="flex items-center"><span className="mr-2">💻</span> Client</div>
                <div className="flex items-center"><span className="mr-2">☁️</span> External</div>
              </div>
            </div>
          </div>
        </div>

        {/* Node Details Panel */}
        <div className="bg-dark-card border border-dark-border rounded-xl p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Node Details</h3>
          
          {selectedNode ? (
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <div className={cn(
                  'w-12 h-12 rounded-lg border-2 flex items-center justify-center text-xl',
                  getStatusColor(selectedNode.status)
                )}>
                  {getNodeIcon(selectedNode.type)}
                </div>
                <div>
                  <h4 className="text-white font-medium">{selectedNode.label}</h4>
                  <p className="text-gray-400 text-sm capitalize">{selectedNode.type}</p>
                </div>
              </div>

              <div className="space-y-3 pt-4 border-t border-dark-border">
                <div className="flex justify-between">
                  <span className="text-gray-400">IP Address</span>
                  <span className="text-white font-mono">{selectedNode.ip}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Status</span>
                  <span className={cn(
                    'px-2 py-0.5 rounded text-xs font-medium',
                    selectedNode.status === 'active' && 'bg-green-500/20 text-green-400',
                    selectedNode.status === 'warning' && 'bg-yellow-500/20 text-yellow-400',
                    selectedNode.status === 'idle' && 'bg-gray-500/20 text-gray-400'
                  )}>
                    {selectedNode.status}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Traffic</span>
                  <span className="text-white">{formatTraffic(selectedNode.traffic)}/s</span>
                </div>
              </div>

              {/* Connections for this node */}
              <div className="pt-4 border-t border-dark-border">
                <h5 className="text-sm font-medium text-gray-400 mb-3">Connections</h5>
                <div className="space-y-2">
                  {topology.edges
                    .filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
                    .map((edge, i) => {
                      const connectedId = edge.source === selectedNode.id ? edge.target : edge.source
                      const connectedNode = topology.nodes.find(n => n.id === connectedId)
                      return (
                        <div key={i} className="flex items-center justify-between text-sm p-2 bg-dark-bg rounded">
                          <span className="text-white">{connectedNode?.label}</span>
                          <span className="text-gray-400">{edge.protocol}</span>
                        </div>
                      )
                    })}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center text-gray-400 py-12">
              <p>Select a node to view details</p>
            </div>
          )}

          {/* Network Stats */}
          <div className="mt-6 pt-4 border-t border-dark-border">
            <h5 className="text-sm font-medium text-gray-400 mb-3">Network Summary</h5>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-dark-bg rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-white">{topology.nodes.length}</div>
                <div className="text-xs text-gray-400">Nodes</div>
              </div>
              <div className="bg-dark-bg rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-white">{topology.edges.length}</div>
                <div className="text-xs text-gray-400">Connections</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
