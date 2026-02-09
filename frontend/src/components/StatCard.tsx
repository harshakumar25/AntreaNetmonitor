import { ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface StatCardProps {
  title: string
  value: string | number
  change?: string
  changeType?: 'positive' | 'negative' | 'neutral'
  icon?: ReactNode
  className?: string
}

export default function StatCard({
  title,
  value,
  change,
  changeType = 'neutral',
  icon,
  className
}: StatCardProps) {
  return (
    <div className={cn(
      'bg-dark-card border border-dark-border rounded-xl p-6 hover:border-primary-500/50 transition-colors',
      className
    )}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-gray-400 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold text-white mt-2">{value}</p>
          {change && (
            <p className={cn(
              'text-sm mt-2 font-medium',
              changeType === 'positive' && 'text-green-400',
              changeType === 'negative' && 'text-red-400',
              changeType === 'neutral' && 'text-gray-400'
            )}>
              {changeType === 'positive' && '↑ '}
              {changeType === 'negative' && '↓ '}
              {change}
            </p>
          )}
        </div>
        {icon && (
          <div className="p-3 bg-primary-500/20 rounded-lg text-primary-400">
            {icon}
          </div>
        )}
      </div>
    </div>
  )
}
