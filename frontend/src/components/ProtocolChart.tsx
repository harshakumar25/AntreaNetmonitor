import { useMemo } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { getProtocolColor } from '@/lib/utils'

interface ProtocolChartProps {
  data: Record<string, number>
}

export default function ProtocolChart({ data }: ProtocolChartProps) {
  const chartData = useMemo(() => {
    return Object.entries(data)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
  }, [data])

  const total = useMemo(() => 
    chartData.reduce((sum, item) => sum + item.value, 0),
    [chartData]
  )

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-6">
      <h3 className="text-lg font-semibold text-white mb-4">Protocol Distribution</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              dataKey="value"
            >
              {chartData.map((entry) => (
                <Cell 
                  key={`cell-${entry.name}`} 
                  fill={getProtocolColor(entry.name)}
                  stroke="transparent"
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '8px',
              }}
              formatter={(value: number, name: string) => [
                `${((value / total) * 100).toFixed(1)}%`,
                name
              ]}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      
      {/* Legend */}
      <div className="mt-4 grid grid-cols-2 gap-2">
        {chartData.slice(0, 6).map((item) => (
          <div key={item.name} className="flex items-center text-sm">
            <span 
              className="w-3 h-3 rounded-full mr-2"
              style={{ backgroundColor: getProtocolColor(item.name) }}
            />
            <span className="text-gray-400">{item.name}</span>
            <span className="ml-auto text-white font-medium">
              {((item.value / total) * 100).toFixed(0)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
