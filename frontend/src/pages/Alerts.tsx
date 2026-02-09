import { useState, useEffect } from 'react'
import { Bell, CheckCircle, AlertTriangle, Info, XCircle } from 'lucide-react'
import type { Alert } from '@/types'
import { cn, getRelativeTime } from '@/lib/utils'

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [filter, setFilter] = useState<'all' | 'unresolved' | 'resolved'>('all')
  const [typeFilter, setTypeFilter] = useState<'all' | 'critical' | 'warning' | 'info'>('all')

  useEffect(() => {
    // Fetch alerts from API
    fetch('/api/v1/alerts')
      .then(res => res.json())
      .then(data => setAlerts(data.alerts || []))
      .catch(() => {
        // Use mock data if API fails
        setAlerts([
          { id: '1', type: 'critical', title: 'High CPU Usage', message: 'Server CPU usage exceeded 90%', source: '192.168.1.10', timestamp: new Date(Date.now() - 2 * 60000).toISOString(), resolved: false },
          { id: '2', type: 'warning', title: 'Memory Warning', message: 'Available memory below 20%', source: '192.168.1.20', timestamp: new Date(Date.now() - 5 * 60000).toISOString(), resolved: false },
          { id: '3', type: 'info', title: 'New Connection', message: 'New device connected to network', source: '192.168.1.50', timestamp: new Date(Date.now() - 10 * 60000).toISOString(), resolved: true },
          { id: '4', type: 'critical', title: 'DDoS Attempt', message: 'Potential DDoS attack detected from multiple sources', source: '203.0.113.50', timestamp: new Date(Date.now() - 15 * 60000).toISOString(), resolved: false },
          { id: '5', type: 'warning', title: 'Disk Space', message: 'Disk space below 10% on volume /dev/sda1', source: '192.168.1.10', timestamp: new Date(Date.now() - 30 * 60000).toISOString(), resolved: true },
          { id: '6', type: 'info', title: 'Scheduled Backup', message: 'Daily backup completed successfully', source: '192.168.1.20', timestamp: new Date(Date.now() - 60 * 60000).toISOString(), resolved: true },
        ])
      })
  }, [])

  const resolveAlert = (id: string) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, resolved: true } : a))
  }

  const resolveAll = () => {
    setAlerts(prev => prev.map(a => ({ ...a, resolved: true })))
  }

  const filteredAlerts = alerts.filter(alert => {
    const matchesStatus = filter === 'all' || 
      (filter === 'unresolved' && !alert.resolved) ||
      (filter === 'resolved' && alert.resolved)
    
    const matchesType = typeFilter === 'all' || alert.type === typeFilter
    
    return matchesStatus && matchesType
  })

  const stats = {
    total: alerts.length,
    unresolved: alerts.filter(a => !a.resolved).length,
    critical: alerts.filter(a => a.type === 'critical' && !a.resolved).length,
    warning: alerts.filter(a => a.type === 'warning' && !a.resolved).length,
  }

  const getIcon = (type: string) => {
    switch (type) {
      case 'critical': return <XCircle className="w-5 h-5 text-red-400" />
      case 'warning': return <AlertTriangle className="w-5 h-5 text-yellow-400" />
      case 'info': return <Info className="w-5 h-5 text-blue-400" />
      default: return <Bell className="w-5 h-5 text-gray-400" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Alerts & Notifications</h1>
          <p className="text-gray-400 mt-1">System alerts and security notifications</p>
        </div>
        {stats.unresolved > 0 && (
          <button
            onClick={resolveAll}
            className="px-4 py-2 bg-green-500/20 text-green-400 rounded-lg font-medium hover:bg-green-500/30 transition-colors"
          >
            <CheckCircle className="w-4 h-4 inline mr-2" />
            Resolve All
          </button>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-dark-card border border-dark-border rounded-xl p-4">
          <div className="text-gray-400 text-sm">Total Alerts</div>
          <div className="text-2xl font-bold text-white mt-1">{stats.total}</div>
        </div>
        <div className="bg-dark-card border border-dark-border rounded-xl p-4">
          <div className="text-gray-400 text-sm">Unresolved</div>
          <div className="text-2xl font-bold text-yellow-400 mt-1">{stats.unresolved}</div>
        </div>
        <div className="bg-dark-card border border-dark-border rounded-xl p-4">
          <div className="text-gray-400 text-sm">Critical</div>
          <div className="text-2xl font-bold text-red-400 mt-1">{stats.critical}</div>
        </div>
        <div className="bg-dark-card border border-dark-border rounded-xl p-4">
          <div className="text-gray-400 text-sm">Warnings</div>
          <div className="text-2xl font-bold text-orange-400 mt-1">{stats.warning}</div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 bg-dark-card border border-dark-border rounded-xl p-4">
        <div className="flex rounded-lg overflow-hidden border border-dark-border">
          {(['all', 'unresolved', 'resolved'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                'px-4 py-2 text-sm font-medium transition-colors capitalize',
                filter === f 
                  ? 'bg-primary-500 text-white' 
                  : 'bg-dark-bg text-gray-400 hover:text-white'
              )}
            >
              {f}
            </button>
          ))}
        </div>

        <div className="flex rounded-lg overflow-hidden border border-dark-border">
          {(['all', 'critical', 'warning', 'info'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={cn(
                'px-4 py-2 text-sm font-medium transition-colors capitalize',
                typeFilter === t 
                  ? 'bg-primary-500 text-white' 
                  : 'bg-dark-bg text-gray-400 hover:text-white'
              )}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="ml-auto text-sm text-gray-400">
          Showing {filteredAlerts.length} of {alerts.length} alerts
        </div>
      </div>

      {/* Alerts List */}
      <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
        <div className="divide-y divide-dark-border">
          {filteredAlerts.length === 0 ? (
            <div className="p-12 text-center">
              <Bell className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">No alerts match your filters</p>
            </div>
          ) : (
            filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                className={cn(
                  'p-4 hover:bg-dark-border/30 transition-colors',
                  alert.resolved && 'opacity-60'
                )}
              >
                <div className="flex items-start">
                  <div className="mr-4 mt-0.5">{getIcon(alert.type)}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3">
                      <h4 className="text-white font-medium">{alert.title}</h4>
                      <span className={cn(
                        'px-2 py-0.5 rounded text-xs font-medium',
                        alert.type === 'critical' && 'bg-red-500/20 text-red-400',
                        alert.type === 'warning' && 'bg-yellow-500/20 text-yellow-400',
                        alert.type === 'info' && 'bg-blue-500/20 text-blue-400'
                      )}>
                        {alert.type}
                      </span>
                      {alert.resolved && (
                        <span className="flex items-center text-green-400 text-xs">
                          <CheckCircle className="w-3 h-3 mr-1" />
                          Resolved
                        </span>
                      )}
                    </div>
                    <p className="text-gray-400 mt-1">{alert.message}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                      <span>Source: {alert.source}</span>
                      <span>{getRelativeTime(alert.timestamp)}</span>
                    </div>
                  </div>
                  {!alert.resolved && (
                    <button
                      onClick={() => resolveAlert(alert.id)}
                      className="ml-4 px-3 py-1.5 text-sm bg-green-500/20 text-green-400 rounded-lg hover:bg-green-500/30 transition-colors"
                    >
                      Resolve
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
