import type { Alert } from '@/types'
import { cn, getRelativeTime, getAlertIcon } from '@/lib/utils'
import { CheckCircle, XCircle } from 'lucide-react'

interface AlertListProps {
  alerts: Alert[]
  onResolve?: (id: string) => void
}

export default function AlertList({ alerts, onResolve }: AlertListProps) {
  return (
    <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-dark-border flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Recent Alerts</h3>
        <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-sm font-medium">
          {alerts.filter(a => !a.resolved).length} unresolved
        </span>
      </div>
      
      <div className="divide-y divide-dark-border max-h-96 overflow-y-auto">
        {alerts.length === 0 ? (
          <div className="p-6 text-center text-gray-400">
            No alerts to display
          </div>
        ) : (
          alerts.map((alert) => (
            <div
              key={alert.id}
              className={cn(
                'p-4 hover:bg-dark-border/30 transition-colors',
                alert.resolved && 'opacity-50'
              )}
            >
              <div className="flex items-start">
                <span className="text-2xl mr-3">{getAlertIcon(alert.type)}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
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
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    )}
                  </div>
                  <p className="text-sm text-gray-400 mt-1">{alert.message}</p>
                  <div className="flex items-center mt-2 text-xs text-gray-500">
                    <span>Source: {alert.source}</span>
                    <span className="mx-2">•</span>
                    <span>{getRelativeTime(alert.timestamp)}</span>
                  </div>
                </div>
                {!alert.resolved && onResolve && (
                  <button
                    onClick={() => onResolve(alert.id)}
                    className="ml-4 p-2 text-gray-400 hover:text-green-400 hover:bg-green-500/10 rounded transition-colors"
                    title="Mark as resolved"
                  >
                    <XCircle className="w-5 h-5" />
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
