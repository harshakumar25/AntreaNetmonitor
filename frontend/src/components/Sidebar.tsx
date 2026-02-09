import { NavLink } from 'react-router-dom'
import { 
  LayoutDashboard, 
  Network, 
  AlertTriangle, 
  Box,
  Activity,
  Settings,
  GitCompare
} from 'lucide-react'
import { cn } from '@/lib/utils'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Live Packets', href: '/packets', icon: Activity },
  { name: 'Topology', href: '/topology', icon: Network },
  { name: 'Alerts', href: '/alerts', icon: AlertTriangle },
  { name: 'BPF Compare', href: '/bpf', icon: GitCompare, badge: 'NEW' },
]

export default function Sidebar() {
  return (
    <aside className="w-64 bg-dark-card border-r border-dark-border flex flex-col">
      {/* Logo */}
      <div className="h-16 flex items-center px-6 border-b border-dark-border">
        <Box className="w-8 h-8 text-primary-500" />
        <span className="ml-3 text-lg font-bold gradient-text">Antrea NetMonitor</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.href}
            className={({ isActive }) =>
              cn(
                'flex items-center px-4 py-3 rounded-lg transition-all duration-200',
                isActive
                  ? 'bg-primary-500/20 text-primary-400 border-l-4 border-primary-500'
                  : 'text-gray-400 hover:bg-dark-border/50 hover:text-white'
              )
            }
          >
            <item.icon className="w-5 h-5 mr-3" />
            <span className="font-medium">{item.name}</span>
            {item.badge && (
              <span className="ml-auto px-2 py-0.5 text-xs font-semibold bg-green-500/20 text-green-400 rounded-full">
                {item.badge}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Settings */}
      <div className="p-3 border-t border-dark-border">
        <button className="flex items-center w-full px-4 py-3 rounded-lg text-gray-400 hover:bg-dark-border/50 hover:text-white transition-colors">
          <Settings className="w-5 h-5 mr-3" />
          <span className="font-medium">Settings</span>
        </button>
      </div>

      {/* Status */}
      <div className="p-4 mx-3 mb-3 bg-dark-border/50 rounded-lg">
        <div className="flex items-center text-sm">
          <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse mr-2" />
          <span className="text-gray-400">System Online</span>
        </div>
        <p className="text-xs text-gray-500 mt-1">v1.0.0</p>
      </div>
    </aside>
  )
}
