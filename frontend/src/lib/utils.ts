import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return '0 B'

  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`
}

export function formatNumber(num: number): string {
  if (num >= 1000000) {
    return (num / 1000000).toFixed(1) + 'M'
  }
  if (num >= 1000) {
    return (num / 1000).toFixed(1) + 'K'
  }
  return num.toFixed(0)
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${(ms / 60000).toFixed(1)}m`
}

export function getProtocolColor(protocol: string): string {
  const colors: Record<string, string> = {
    TCP: '#3b82f6',
    UDP: '#22c55e',
    HTTP: '#f59e0b',
    HTTPS: '#8b5cf6',
    DNS: '#ec4899',
    ICMP: '#06b6d4',
    SSH: '#84cc16',
    FTP: '#f97316',
  }
  return colors[protocol] || '#64748b'
}

export function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    active: 'text-green-400',
    warning: 'text-yellow-400',
    critical: 'text-red-400',
    idle: 'text-gray-400',
    info: 'text-blue-400',
  }
  return colors[status] || 'text-gray-400'
}

export function getAlertIcon(type: string): string {
  const icons: Record<string, string> = {
    warning: '⚠️',
    critical: '🚨',
    info: 'ℹ️',
  }
  return icons[type] || 'ℹ️'
}

export function truncateIP(ip: string, maxLength = 15): string {
  return ip.length > maxLength ? ip.slice(0, maxLength) + '...' : ip
}

export function getRelativeTime(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  
  const seconds = Math.floor(diffMs / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)

  if (days > 0) return `${days}d ago`
  if (hours > 0) return `${hours}h ago`
  if (minutes > 0) return `${minutes}m ago`
  if (seconds > 0) return `${seconds}s ago`
  return 'Just now'
}
