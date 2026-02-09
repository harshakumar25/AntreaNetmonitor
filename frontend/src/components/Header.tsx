import { useState, useEffect } from 'react'
import { Bell, Search, Wifi, WifiOff } from 'lucide-react'
import { cn } from '@/lib/utils'

interface HeaderProps {
  isConnected?: boolean
}

export default function Header({ isConnected = true }: HeaderProps) {
  const [currentTime, setCurrentTime] = useState(new Date())
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])

  return (
    <header className="h-16 bg-dark-card border-b border-dark-border flex items-center justify-between px-6">
      {/* Search */}
      <div className="relative w-96">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
        <input
          type="text"
          placeholder="Search packets, IPs, protocols..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full pl-10 pr-4 py-2 bg-dark-bg border border-dark-border rounded-lg 
                     text-white placeholder-gray-500 focus:outline-none focus:border-primary-500
                     transition-colors"
        />
      </div>

      {/* Right section */}
      <div className="flex items-center space-x-6">
        {/* Connection Status */}
        <div className={cn(
          'flex items-center px-3 py-1.5 rounded-full text-sm font-medium',
          isConnected 
            ? 'bg-green-500/20 text-green-400' 
            : 'bg-red-500/20 text-red-400'
        )}>
          {isConnected ? (
            <>
              <Wifi className="w-4 h-4 mr-2" />
              <span>Live</span>
            </>
          ) : (
            <>
              <WifiOff className="w-4 h-4 mr-2" />
              <span>Disconnected</span>
            </>
          )}
        </div>

        {/* Time */}
        <div className="text-gray-400 text-sm font-mono">
          {currentTime.toLocaleTimeString()}
        </div>

        {/* Notifications */}
        <button className="relative p-2 hover:bg-dark-border rounded-lg transition-colors">
          <Bell className="w-5 h-5 text-gray-400" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
        </button>

        {/* Profile */}
        <div className="w-9 h-9 bg-gradient-to-br from-primary-500 to-purple-500 rounded-full flex items-center justify-center">
          <span className="text-white font-medium text-sm">A</span>
        </div>
      </div>
    </header>
  )
}
