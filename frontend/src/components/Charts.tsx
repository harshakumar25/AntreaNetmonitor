import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { formatBytes, formatNumber } from '@/lib/utils'

interface ThroughputChartProps {
  data: Array<{
    time: string
    bytesIn: number
    bytesOut: number
  }>
}

export function ThroughputChart({ data }: ThroughputChartProps) {
  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-6">
      <h3 className="text-lg font-semibold text-white mb-4">Network Throughput</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorIn" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorOut" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
            <YAxis stroke="#64748b" fontSize={12} tickFormatter={(v) => formatBytes(v)} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '8px',
              }}
              labelStyle={{ color: '#94a3b8' }}
              formatter={(value: number) => [formatBytes(value), '']}
            />
            <Legend />
            <Area
              type="monotone"
              dataKey="bytesIn"
              name="Inbound"
              stroke="#3b82f6"
              fill="url(#colorIn)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="bytesOut"
              name="Outbound"
              stroke="#22c55e"
              fill="url(#colorOut)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

interface PacketRateChartProps {
  data: Array<{
    time: string
    packets: number
  }>
}

export function PacketRateChart({ data }: PacketRateChartProps) {
  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-6">
      <h3 className="text-lg font-semibold text-white mb-4">Packet Rate</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
            <YAxis stroke="#64748b" fontSize={12} tickFormatter={(v) => formatNumber(v)} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '8px',
              }}
              labelStyle={{ color: '#94a3b8' }}
              formatter={(value: number) => [formatNumber(value) + ' pkt/s', 'Rate']}
            />
            <Line
              type="monotone"
              dataKey="packets"
              stroke="#8b5cf6"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 6, fill: '#8b5cf6' }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

interface LatencyChartProps {
  data: Array<{
    time: string
    avg: number
    p95: number
    p99: number
  }>
}

export function LatencyChart({ data }: LatencyChartProps) {
  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-6">
      <h3 className="text-lg font-semibold text-white mb-4">Network Latency</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
            <YAxis stroke="#64748b" fontSize={12} tickFormatter={(v) => `${v}ms`} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '8px',
              }}
              labelStyle={{ color: '#94a3b8' }}
              formatter={(value: number) => [`${value.toFixed(1)}ms`, '']}
            />
            <Legend />
            <Line
              type="monotone"
              dataKey="avg"
              name="Average"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={false}
            />
            <Line
              type="monotone"
              dataKey="p95"
              name="P95"
              stroke="#f59e0b"
              strokeWidth={2}
              dot={false}
            />
            <Line
              type="monotone"
              dataKey="p99"
              name="P99"
              stroke="#ef4444"
              strokeWidth={2}
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
