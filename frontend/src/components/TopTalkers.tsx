import { formatBytes } from '@/lib/utils'
import type { IPStats } from '@/types'

interface TopTalkersProps {
  title: string
  data: IPStats[]
  type: 'source' | 'destination'
}

export default function TopTalkers({ title, data, type }: TopTalkersProps) {
  const maxBytes = Math.max(...data.map(d => d.bytes), 1)

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-6">
      <h3 className="text-lg font-semibold text-white mb-4">{title}</h3>
      <div className="space-y-4">
        {data.length === 0 ? (
          <p className="text-gray-400 text-sm">No data available</p>
        ) : (
          data.map((item, index) => (
            <div key={item.ip} className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <span className="w-6 h-6 bg-dark-border rounded flex items-center justify-center text-gray-400 text-xs mr-3">
                    {index + 1}
                  </span>
                  <span className="text-white font-mono">{item.ip}</span>
                </div>
                <span className="text-gray-400">{formatBytes(item.bytes)}</span>
              </div>
              <div className="h-2 bg-dark-border rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all duration-500 ${
                    type === 'source' ? 'bg-primary-500' : 'bg-purple-500'
                  }`}
                  style={{ width: `${(item.bytes / maxBytes) * 100}%` }}
                />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
