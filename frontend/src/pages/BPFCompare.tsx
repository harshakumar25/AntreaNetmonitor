import { useState, useCallback, useEffect } from 'react'
import { 
  Code2, 
  Play, 
  RefreshCw, 
  CheckCircle, 
  XCircle, 
  AlertTriangle,
  Copy,
  BookOpen,
  Zap,
  ArrowLeftRight,
  Download,
  BarChart3,
  Layers,
  FileCode,
  Upload,
  Server,
  FileUp
} from 'lucide-react'

interface BPFInstruction {
  index: number
  op: number
  jt: number
  jf: number
  k: number
  desc: string
}

interface BPFProgram {
  source: string
  expression: string
  instructions: BPFInstruction[]
  count: number
  error?: string
}

interface ComparisonResult {
  expression: string
  tcpdump: BPFProgram
  antrea: BPFProgram
  match: boolean
  instructionDiff: number
  analysis: string[]
  differences: { index: number; tcpdump: string; antrea: string }[]
}

interface BPFMetrics {
  expression: string
  instructionCount: number
  jumpCount: number
  loadCount: number
  compareCount: number
  returnCount: number
  maxJumpDistance: number
  hasIPv6: boolean
  hasFragCheck: boolean
  complexityScore: number
  estimatedCycles: number
}

interface BatchSummary {
  total: number
  matches: number
  matchRate: number
  avgTcpdumpInst: number
  avgAntreaInst: number
  avgInstructionDiff: number
}

interface AntreaStatus {
  connected: boolean
  clusterName?: string
  antreaVersion?: string
  agentCount?: number
  controllerReady: boolean
  message: string
}

interface PcapTestResult {
  expression: string
  totalPackets: number
  matchedPackets: number
  filterRate: number
  bpfProgram: BPFProgram
}

interface K8sPreset {
  name: string
  expression: string
  description: string
  useCase: string
}

interface BPFOptimization {
  type: string
  severity: 'info' | 'warning' | 'error'
  description: string
  suggestion: string
  impact: string
}

interface BPFFlowNode {
  index: number
  instruction: string
  type: string
  next?: number
  nextTrue?: number
  nextFalse?: number
  isTerminal: boolean
  reachable: boolean
}

interface AnalysisReport {
  expression: string
  metrics: BPFMetrics
  optimizations: BPFOptimization[]
  kubernetesHints: string[]
  generatedAt: string
}

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8085'

export default function BPFCompare() {
  const [expression, setExpression] = useState('tcp port 80')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ComparisonResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showOpcodes, setShowOpcodes] = useState(false)
  const [metrics, setMetrics] = useState<BPFMetrics | null>(null)
  const [showMetrics, setShowMetrics] = useState(false)
  const [showExport, setShowExport] = useState(false)
  const [exportFormat, setExportFormat] = useState<'c' | 'go' | 'hex' | 'raw'>('c')
  const [exportOutput, setExportOutput] = useState<string>('')
  const [showBatch, setShowBatch] = useState(false)
  const [batchSummary, setBatchSummary] = useState<BatchSummary | null>(null)
  const [antreaStatus, setAntreaStatus] = useState<AntreaStatus | null>(null)
  const [showPcapUpload, setShowPcapUpload] = useState(false)
  const [pcapResult, setPcapResult] = useState<PcapTestResult | null>(null)
  const [uploadedPcap, setUploadedPcap] = useState<string | null>(null)
  const [k8sPresets, setK8sPresets] = useState<K8sPreset[]>([])
  const [showK8sPresets, setShowK8sPresets] = useState(false)
  const [optimizations, setOptimizations] = useState<BPFOptimization[]>([])
  const [showOptimizations, setShowOptimizations] = useState(false)
  const [flowGraph, setFlowGraph] = useState<BPFFlowNode[]>([])
  const [showFlow, setShowFlow] = useState(false)
  const [analysisReport, setAnalysisReport] = useState<AnalysisReport | null>(null)
  const [showReport, setShowReport] = useState(false)

  const commonFilters = [
    { expr: 'tcp', desc: 'All TCP traffic' },
    { expr: 'udp', desc: 'All UDP traffic' },
    { expr: 'icmp', desc: 'All ICMP traffic' },
    { expr: 'tcp port 80', desc: 'HTTP traffic' },
    { expr: 'tcp port 443', desc: 'HTTPS traffic' },
    { expr: 'udp port 53', desc: 'DNS traffic' },
    { expr: 'tcp port 22', desc: 'SSH traffic' },
    { expr: 'src host 192.168.1.1', desc: 'Traffic from specific host' },
    { expr: 'dst port 8080', desc: 'Traffic to port 8080' },
    { expr: 'tcp and port 80 and host 10.0.0.1', desc: 'Combined filter' },
  ]

  const handleCompare = useCallback(async () => {
    if (!expression.trim()) return
    
    setLoading(true)
    setError(null)
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/compare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expression: expression.trim() })
      })
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      
      const data = await response.json()
      setResult(data)
      
      // Also fetch metrics
      const metricsRes = await fetch(`${API_BASE}/api/v1/bpf/metrics`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expression: expression.trim() })
      })
      if (metricsRes.ok) {
        setMetrics(await metricsRes.json())
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to compare BPF')
    } finally {
      setLoading(false)
    }
  }, [expression])

  const handleExport = useCallback(async (format: 'c' | 'go' | 'hex' | 'raw') => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/export`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expression: expression.trim(), format })
      })
      if (response.ok) {
        const data = await response.json()
        setExportOutput(data.output)
        setExportFormat(format)
        setShowExport(true)
      }
    } catch (err) {
      console.error('Export failed:', err)
    }
  }, [expression])

  const handleBatchCompare = useCallback(async () => {
    const expressions = commonFilters.map(f => f.expr)
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expressions })
      })
      if (response.ok) {
        const data = await response.json()
        setBatchSummary(data.summary)
        setShowBatch(true)
      }
    } catch (err) {
      console.error('Batch compare failed:', err)
    }
  }, [])

  // Fetch Antrea status on mount
  const fetchAntreaStatus = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/antrea/status`)
      if (response.ok) {
        setAntreaStatus(await response.json())
      }
    } catch (err) {
      console.error('Failed to fetch Antrea status:', err)
    }
  }, [])

  // Handle pcap file upload
  const handlePcapUpload = useCallback(async (file: File) => {
    const formData = new FormData()
    formData.append('pcap', file)
    
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/pcap/upload`, {
        method: 'POST',
        body: formData
      })
      if (response.ok) {
        const data = await response.json()
        setUploadedPcap(data.path)
        // Test current expression on uploaded pcap
        testFilterOnPcap(data.path, expression)
      }
    } catch (err) {
      console.error('Pcap upload failed:', err)
    }
  }, [expression])

  // Test filter on pcap
  const testFilterOnPcap = useCallback(async (pcapPath: string, expr: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/pcap/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pcapPath, expression: expr })
      })
      if (response.ok) {
        setPcapResult(await response.json())
      }
    } catch (err) {
      console.error('Pcap test failed:', err)
    }
  }, [])

  // Fetch K8s presets
  const fetchK8sPresets = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/k8s-presets`)
      if (response.ok) {
        const data = await response.json()
        setK8sPresets(data.presets)
        setShowK8sPresets(true)
      }
    } catch (err) {
      console.error('Failed to fetch K8s presets:', err)
    }
  }, [])

  // Fetch optimizations
  const fetchOptimizations = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/optimize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expression: expression.trim() })
      })
      if (response.ok) {
        const data = await response.json()
        setOptimizations(data.optimizations)
        setShowOptimizations(true)
      }
    } catch (err) {
      console.error('Failed to fetch optimizations:', err)
    }
  }, [expression])

  // Fetch flow graph
  const fetchFlowGraph = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/flow`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expression: expression.trim() })
      })
      if (response.ok) {
        const data = await response.json()
        setFlowGraph(data.flow)
        setShowFlow(true)
      }
    } catch (err) {
      console.error('Failed to fetch flow graph:', err)
    }
  }, [expression])

  // Generate full report
  const generateReport = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/v1/bpf/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expression: expression.trim() })
      })
      if (response.ok) {
        const data = await response.json()
        setAnalysisReport(data.report)
        setShowReport(true)
      }
    } catch (err) {
      console.error('Failed to generate report:', err)
    }
  }, [expression])

  // Fetch Antrea status on component mount
  useEffect(() => {
    fetchAntreaStatus()
  }, [fetchAntreaStatus])

  const copyBPF = (program: BPFProgram) => {
    const text = program.instructions
      .map(i => `{ 0x${i.op.toString(16).padStart(2, '0')}, ${i.jt}, ${i.jf}, 0x${i.k.toString(16).padStart(8, '0')} },`)
      .join('\n')
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Code2 className="w-8 h-8 text-blue-400" />
              <h1 className="text-3xl font-bold">Antrea BPF Comparison Tool</h1>
              <span className="px-2 py-1 text-xs font-semibold bg-green-500/20 text-green-400 rounded-full">
                LFX 2026
              </span>
            </div>
            {/* Antrea Status Badge */}
            {antreaStatus && (
              <div className={`flex items-center gap-2 px-3 py-2 rounded-lg ${
                antreaStatus.connected 
                  ? 'bg-green-900/30 border border-green-500/50' 
                  : 'bg-yellow-900/30 border border-yellow-500/50'
              }`}>
                <span className={`w-2 h-2 rounded-full ${
                  antreaStatus.connected ? 'bg-green-500 animate-pulse' : 'bg-yellow-500'
                }`} />
                <span className="text-sm">
                  {antreaStatus.connected 
                    ? `Antrea ${antreaStatus.antreaVersion || ''} (${antreaStatus.agentCount} agents)`
                    : 'Antrea: Simulated'}
                </span>
              </div>
            )}
          </div>
          <p className="text-gray-400 mt-2">
            Compare Antrea's PacketCapture BPF generation with tcpdump/libpcap - CNCF LFX Mentorship Project
          </p>
        </div>

        {/* Input Section */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Filter Expression
          </label>
          <div className="flex gap-4">
            <input
              type="text"
              value={expression}
              onChange={(e) => setExpression(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCompare()}
              placeholder="e.g., tcp port 80 and host 192.168.1.1"
              className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
            />
            <button
              onClick={handleCompare}
              disabled={loading || !expression.trim()}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded-lg font-medium flex items-center gap-2 transition-colors"
            >
              {loading ? (
                <RefreshCw className="w-5 h-5 animate-spin" />
              ) : (
                <Play className="w-5 h-5" />
              )}
              Compare
            </button>
          </div>

          {/* Action Buttons */}
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              onClick={() => handleExport('c')}
              disabled={!result}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-500 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <FileCode className="w-4 h-4" />
              Export C
            </button>
            <button
              onClick={() => handleExport('go')}
              disabled={!result}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-500 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <FileCode className="w-4 h-4" />
              Export Go
            </button>
            <button
              onClick={() => setShowMetrics(!showMetrics)}
              disabled={!metrics}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 disabled:text-gray-500 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <BarChart3 className="w-4 h-4" />
              Metrics
            </button>
            <button
              onClick={handleBatchCompare}
              className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <Layers className="w-4 h-4" />
              Batch Compare
            </button>
            <button
              onClick={() => setShowPcapUpload(!showPcapUpload)}
              className="px-3 py-1.5 bg-purple-700 hover:bg-purple-600 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <Upload className="w-4 h-4" />
              Test on PCAP
            </button>
            <button
              onClick={fetchAntreaStatus}
              className="px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <Server className="w-4 h-4" />
              Refresh Antrea
            </button>
            <button
              onClick={fetchK8sPresets}
              className="px-3 py-1.5 bg-green-700 hover:bg-green-600 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <BookOpen className="w-4 h-4" />
              K8s Presets
            </button>
            <button
              onClick={fetchOptimizations}
              disabled={!expression.trim()}
              className="px-3 py-1.5 bg-yellow-700 hover:bg-yellow-600 disabled:bg-gray-800 disabled:text-gray-500 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <Zap className="w-4 h-4" />
              Optimize
            </button>
            <button
              onClick={fetchFlowGraph}
              disabled={!expression.trim()}
              className="px-3 py-1.5 bg-indigo-700 hover:bg-indigo-600 disabled:bg-gray-800 disabled:text-gray-500 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <ArrowLeftRight className="w-4 h-4" />
              Flow Graph
            </button>
            <button
              onClick={generateReport}
              disabled={!expression.trim()}
              className="px-3 py-1.5 bg-red-700 hover:bg-red-600 disabled:bg-gray-800 disabled:text-gray-500 rounded text-sm flex items-center gap-2 transition-colors"
            >
              <Download className="w-4 h-4" />
              Report
            </button>
          </div>

          {/* Quick Filters */}
          <div className="mt-4">
            <div className="text-sm text-gray-400 mb-2">Quick filters:</div>
            <div className="flex flex-wrap gap-2">
              {commonFilters.map((f) => (
                <button
                  key={f.expr}
                  onClick={() => setExpression(f.expr)}
                  className="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm font-mono transition-colors"
                  title={f.desc}
                >
                  {f.expr}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* PCAP Upload Panel */}
        {showPcapUpload && (
          <div className="bg-purple-900/30 border border-purple-500/50 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <FileUp className="w-5 h-5 text-purple-400" />
                Test Filter on PCAP File
              </h3>
              <button onClick={() => setShowPcapUpload(false)} className="text-gray-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="flex items-center gap-4">
              <label className="flex-1 flex items-center justify-center gap-2 px-4 py-8 border-2 border-dashed border-purple-500/50 rounded-lg cursor-pointer hover:bg-purple-900/20 transition-colors">
                <Upload className="w-6 h-6 text-purple-400" />
                <span className="text-gray-300">Drop a .pcap file or click to upload</span>
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) handlePcapUpload(file)
                  }}
                />
              </label>
            </div>
            {uploadedPcap && (
              <div className="mt-4 p-3 bg-gray-800 rounded-lg">
                <div className="text-sm text-gray-400">Uploaded: {uploadedPcap.split('/').pop()}</div>
                <button
                  onClick={() => testFilterOnPcap(uploadedPcap, expression)}
                  className="mt-2 px-3 py-1 bg-purple-600 hover:bg-purple-700 rounded text-sm"
                >
                  Re-test with current filter
                </button>
              </div>
            )}
            {pcapResult && (
              <div className="mt-4 grid grid-cols-3 gap-4">
                <MetricCard label="Total Packets" value={pcapResult.totalPackets} color="purple" />
                <MetricCard label="Matched" value={pcapResult.matchedPackets} color="green" />
                <MetricCard label="Filter Rate" value={`${pcapResult.filterRate.toFixed(1)}%`} color="blue" />
              </div>
            )}
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="bg-red-900/50 border border-red-500 rounded-lg p-4 mb-6 flex items-center gap-3">
            <XCircle className="w-5 h-5 text-red-400" />
            <span className="text-red-200">{error}</span>
          </div>
        )}

        {/* Metrics Panel */}
        {showMetrics && metrics && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-blue-400" />
                BPF Complexity Metrics
              </h3>
              <button onClick={() => setShowMetrics(false)} className="text-gray-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricCard label="Instructions" value={metrics.instructionCount} />
              <MetricCard label="Jumps" value={metrics.jumpCount} />
              <MetricCard label="Loads" value={metrics.loadCount} />
              <MetricCard label="Compares" value={metrics.compareCount} />
              <MetricCard label="Max Jump" value={metrics.maxJumpDistance} />
              <MetricCard label="Complexity" value={metrics.complexityScore.toFixed(1)} />
              <MetricCard label="Est. Cycles" value={metrics.estimatedCycles} />
              <MetricCard label="IPv6 Support" value={metrics.hasIPv6 ? '✅' : '❌'} />
            </div>
          </div>
        )}

        {/* Export Modal */}
        {showExport && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Download className="w-5 h-5 text-green-400" />
                Export BPF ({exportFormat.toUpperCase()})
              </h3>
              <div className="flex gap-2">
                <button 
                  onClick={() => navigator.clipboard.writeText(exportOutput)}
                  className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm flex items-center gap-1"
                >
                  <Copy className="w-4 h-4" /> Copy
                </button>
                <button onClick={() => setShowExport(false)} className="text-gray-400 hover:text-white">
                  <XCircle className="w-5 h-5" />
                </button>
              </div>
            </div>
            <pre className="bg-gray-900 p-4 rounded-lg overflow-x-auto text-sm font-mono text-green-400 max-h-96 overflow-y-auto">
              {exportOutput}
            </pre>
          </div>
        )}

        {/* Batch Summary */}
        {showBatch && batchSummary && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Layers className="w-5 h-5 text-purple-400" />
                Batch Comparison Results
              </h3>
              <button onClick={() => setShowBatch(false)} className="text-gray-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <MetricCard label="Total Filters" value={batchSummary.total} />
              <MetricCard label="Exact Matches" value={batchSummary.matches} />
              <MetricCard label="Match Rate" value={`${batchSummary.matchRate.toFixed(1)}%`} color={batchSummary.matchRate > 50 ? 'green' : 'yellow'} />
              <MetricCard label="Avg tcpdump Inst" value={batchSummary.avgTcpdumpInst.toFixed(1)} />
              <MetricCard label="Avg Antrea Inst" value={batchSummary.avgAntreaInst.toFixed(1)} />
              <MetricCard label="Avg Diff" value={batchSummary.avgInstructionDiff.toFixed(1)} />
            </div>
          </div>
        )}

        {/* K8s Presets Panel */}
        {showK8sPresets && k8sPresets.length > 0 && (
          <div className="bg-green-900/30 border border-green-500/50 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-green-400" />
                Kubernetes/Antrea Filter Presets
              </h3>
              <button onClick={() => setShowK8sPresets(false)} className="text-gray-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {k8sPresets.map((preset, i) => (
                <button
                  key={i}
                  onClick={() => {
                    setExpression(preset.expression)
                    setShowK8sPresets(false)
                    handleCompare()
                  }}
                  className="text-left bg-gray-800/50 hover:bg-gray-700/50 p-4 rounded-lg transition-colors"
                >
                  <div className="font-semibold text-green-400">{preset.name}</div>
                  <code className="text-sm text-blue-400 font-mono">{preset.expression}</code>
                  <p className="text-xs text-gray-400 mt-1">{preset.description}</p>
                  <p className="text-xs text-gray-500 mt-1">📌 {preset.useCase}</p>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Optimizations Panel */}
        {showOptimizations && optimizations.length > 0 && (
          <div className="bg-yellow-900/30 border border-yellow-500/50 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Zap className="w-5 h-5 text-yellow-400" />
                Optimization Suggestions
              </h3>
              <button onClick={() => setShowOptimizations(false)} className="text-gray-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-4">
              {optimizations.map((opt, i) => (
                <div key={i} className={`p-4 rounded-lg ${
                  opt.severity === 'warning' ? 'bg-orange-900/30' :
                  opt.severity === 'error' ? 'bg-red-900/30' : 'bg-blue-900/30'
                }`}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`px-2 py-0.5 text-xs rounded ${
                      opt.severity === 'warning' ? 'bg-orange-500/30 text-orange-300' :
                      opt.severity === 'error' ? 'bg-red-500/30 text-red-300' : 'bg-blue-500/30 text-blue-300'
                    }`}>{opt.type}</span>
                    <span className="text-sm font-medium">{opt.description}</span>
                  </div>
                  <p className="text-sm text-gray-300">💡 {opt.suggestion}</p>
                  <p className="text-xs text-gray-500 mt-1">Impact: {opt.impact}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Flow Graph Panel */}
        {showFlow && flowGraph.length > 0 && (
          <div className="bg-indigo-900/30 border border-indigo-500/50 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <ArrowLeftRight className="w-5 h-5 text-indigo-400" />
                BPF Instruction Flow Graph
              </h3>
              <button onClick={() => setShowFlow(false)} className="text-gray-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="overflow-x-auto">
              <div className="flex flex-wrap gap-2 p-4 bg-gray-900/50 rounded-lg min-w-max">
                {flowGraph.map((node, i) => (
                  <div 
                    key={i} 
                    className={`p-2 rounded text-xs font-mono ${
                      node.type === 'return' ? 'bg-green-900/50 border border-green-500' :
                      node.type === 'jump' ? 'bg-purple-900/50 border border-purple-500' :
                      node.type === 'load' ? 'bg-blue-900/50 border border-blue-500' :
                      'bg-gray-700/50 border border-gray-600'
                    }`}
                  >
                    <div className="text-gray-400">[{node.index}]</div>
                    <div className="text-white truncate max-w-32">{node.instruction}</div>
                    {node.type === 'jump' && !node.isTerminal && (
                      <div className="text-xs mt-1">
                        <span className="text-green-400">T→{node.nextTrue}</span>
                        {' '}
                        <span className="text-red-400">F→{node.nextFalse}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-4 flex gap-4 text-sm text-gray-400">
              <span className="flex items-center gap-1"><span className="w-3 h-3 bg-blue-900 border border-blue-500 rounded"></span> Load</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 bg-purple-900 border border-purple-500 rounded"></span> Jump</span>
              <span className="flex items-center gap-1"><span className="w-3 h-3 bg-green-900 border border-green-500 rounded"></span> Return</span>
            </div>
          </div>
        )}

        {/* Analysis Report Panel */}
        {showReport && analysisReport && (
          <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Download className="w-5 h-5 text-red-400" />
                Full Analysis Report
              </h3>
              <div className="flex gap-2">
                <button 
                  onClick={() => {
                    // Export as markdown
                    const blob = new Blob([JSON.stringify(analysisReport, null, 2)], { type: 'application/json' })
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url
                    a.download = `bpf-analysis-${Date.now()}.json`
                    a.click()
                  }}
                  className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-sm flex items-center gap-1"
                >
                  <Download className="w-4 h-4" /> Download JSON
                </button>
                <button onClick={() => setShowReport(false)} className="text-gray-400 hover:text-white">
                  <XCircle className="w-5 h-5" />
                </button>
              </div>
            </div>
            <div className="space-y-4">
              <div className="bg-gray-900/50 p-4 rounded-lg">
                <h4 className="text-sm font-medium text-gray-300 mb-2">Summary Metrics</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-400">Instructions:</span>
                    <span className="ml-2 text-white">{analysisReport.metrics?.instructionCount || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Complexity:</span>
                    <span className="ml-2 text-white">{analysisReport.metrics?.complexityScore?.toFixed(1) || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Est. Cycles:</span>
                    <span className="ml-2 text-white">{analysisReport.metrics?.estimatedCycles || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">IPv6:</span>
                    <span className="ml-2 text-white">{analysisReport.metrics?.hasIPv6 ? '✅' : '❌'}</span>
                  </div>
                </div>
              </div>
              {analysisReport.kubernetesHints && analysisReport.kubernetesHints.length > 0 && (
                <div className="bg-gray-900/50 p-4 rounded-lg">
                  <h4 className="text-sm font-medium text-gray-300 mb-2">Kubernetes Hints</h4>
                  <ul className="space-y-1">
                    {analysisReport.kubernetesHints.map((hint, i) => (
                      <li key={i} className="text-sm text-gray-400 flex items-center gap-2">
                        <span className="text-cyan-400">→</span> {hint}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <>
            {/* Summary Card */}
            <div className={`rounded-lg p-6 mb-6 ${
              result.match 
                ? 'bg-green-900/30 border border-green-500/50' 
                : 'bg-yellow-900/30 border border-yellow-500/50'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {result.match ? (
                    <CheckCircle className="w-8 h-8 text-green-400" />
                  ) : (
                    <AlertTriangle className="w-8 h-8 text-yellow-400" />
                  )}
                  <div>
                    <h2 className="text-xl font-semibold">
                      {result.match ? 'Identical BPF Programs' : 'Programs Differ'}
                    </h2>
                    <p className="text-gray-400">
                      Expression: <code className="text-blue-400">{result.expression}</code>
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <div className="flex items-center gap-4">
                    <div>
                      <div className="text-2xl font-bold text-blue-400">
                        {result.tcpdump.count}
                      </div>
                      <div className="text-sm text-gray-400">tcpdump</div>
                    </div>
                    <ArrowLeftRight className="w-6 h-6 text-gray-500" />
                    <div>
                      <div className="text-2xl font-bold text-purple-400">
                        {result.antrea.count}
                      </div>
                      <div className="text-sm text-gray-400">Antrea</div>
                    </div>
                  </div>
                  {result.instructionDiff !== 0 && (
                    <div className={`text-sm mt-1 ${
                      result.instructionDiff > 0 ? 'text-yellow-400' : 'text-green-400'
                    }`}>
                      {result.instructionDiff > 0 ? '+' : ''}{result.instructionDiff} instructions
                    </div>
                  )}
                </div>
              </div>

              {/* Analysis Notes */}
              {result.analysis.length > 0 && (
                <div className="mt-4 pt-4 border-t border-gray-700">
                  <h3 className="text-sm font-medium text-gray-300 mb-2">Analysis:</h3>
                  <ul className="space-y-1">
                    {result.analysis.map((note, i) => (
                      <li key={i} className="text-gray-400 flex items-center gap-2">
                        <Zap className="w-4 h-4 text-yellow-400" />
                        {note}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Side-by-Side Comparison */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* tcpdump BPF */}
              <BPFProgramCard 
                program={result.tcpdump} 
                title="tcpdump / libpcap"
                color="blue"
                onCopy={() => copyBPF(result.tcpdump)}
              />

              {/* Antrea BPF */}
              <BPFProgramCard 
                program={result.antrea} 
                title="Antrea PacketCapture"
                color="purple"
                onCopy={() => copyBPF(result.antrea)}
              />
            </div>

            {/* Differences Table */}
            {result.differences && result.differences.length > 0 && (
              <div className="mt-6 bg-gray-800 rounded-lg p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-yellow-400" />
                  Instruction Differences
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-700">
                        <th className="text-left py-2 px-4 text-gray-400">Index</th>
                        <th className="text-left py-2 px-4 text-gray-400">tcpdump</th>
                        <th className="text-left py-2 px-4 text-gray-400">Antrea</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.differences.map((diff, i) => (
                        <tr key={i} className="border-b border-gray-700/50">
                          <td className="py-2 px-4 font-mono text-gray-500">[{diff.index}]</td>
                          <td className="py-2 px-4 font-mono text-blue-400">{diff.tcpdump}</td>
                          <td className="py-2 px-4 font-mono text-purple-400">{diff.antrea}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}

        {/* BPF Reference Toggle */}
        <div className="mt-8">
          <button
            onClick={() => setShowOpcodes(!showOpcodes)}
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
          >
            <BookOpen className="w-5 h-5" />
            {showOpcodes ? 'Hide' : 'Show'} BPF Opcode Reference
          </button>
          
          {showOpcodes && <OpcodeReference />}
        </div>
      </div>
    </div>
  )
}

// BPF Program Card Component
function BPFProgramCard({ 
  program, 
  title, 
  color, 
  onCopy 
}: { 
  program: BPFProgram
  title: string
  color: 'blue' | 'purple'
  onCopy: () => void
}) {
  const colorClasses = {
    blue: 'border-blue-500/50 bg-blue-900/20',
    purple: 'border-purple-500/50 bg-purple-900/20'
  }

  const textColor = color === 'blue' ? 'text-blue-400' : 'text-purple-400'

  return (
    <div className={`rounded-lg border ${colorClasses[color]} overflow-hidden`}>
      <div className="px-4 py-3 bg-gray-800/50 flex items-center justify-between">
        <h3 className={`font-semibold ${textColor}`}>{title}</h3>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">{program.count} instructions</span>
          <button
            onClick={onCopy}
            className="p-1 hover:bg-gray-700 rounded transition-colors"
            title="Copy BPF bytecode"
          >
            <Copy className="w-4 h-4 text-gray-400" />
          </button>
        </div>
      </div>
      
      <div className="p-4 max-h-96 overflow-y-auto">
        {program.error ? (
          <div className="text-red-400 flex items-center gap-2">
            <XCircle className="w-4 h-4" />
            {program.error}
          </div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-gray-500 border-b border-gray-700">
                <th className="text-left py-1 w-10">#</th>
                <th className="text-left py-1">Op</th>
                <th className="text-left py-1">Jt</th>
                <th className="text-left py-1">Jf</th>
                <th className="text-left py-1">K</th>
                <th className="text-left py-1">Description</th>
              </tr>
            </thead>
            <tbody>
              {program.instructions.map((inst, i) => (
                <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/50">
                  <td className="py-1 text-gray-500">{i}</td>
                  <td className={`py-1 ${textColor}`}>0x{inst.op.toString(16).padStart(2, '0')}</td>
                  <td className="py-1 text-gray-300">{inst.jt}</td>
                  <td className="py-1 text-gray-300">{inst.jf}</td>
                  <td className="py-1 text-green-400">0x{inst.k.toString(16)}</td>
                  <td className="py-1 text-gray-400 truncate max-w-48" title={inst.desc}>
                    {inst.desc}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// Opcode Reference Component
function OpcodeReference() {
  const opcodes = {
    'Load Instructions': [
      { op: '0x28', name: 'ldh [k]', desc: 'Load half-word (16-bit) from packet at offset k' },
      { op: '0x30', name: 'ldb [k]', desc: 'Load byte (8-bit) from packet at offset k' },
      { op: '0x20', name: 'ld [k]', desc: 'Load word (32-bit) from packet at offset k' },
      { op: '0x48', name: 'ldh [x+k]', desc: 'Load half-word from packet at x + k' },
      { op: '0xb1', name: 'ldxb 4*([k]&0xf)', desc: 'Load IP header length' },
    ],
    'Jump Instructions': [
      { op: '0x15', name: 'jeq #k, jt, jf', desc: 'Jump if A == k' },
      { op: '0x25', name: 'jgt #k, jt, jf', desc: 'Jump if A > k' },
      { op: '0x35', name: 'jge #k, jt, jf', desc: 'Jump if A >= k' },
      { op: '0x45', name: 'jset #k, jt, jf', desc: 'Jump if A & k != 0' },
      { op: '0x05', name: 'ja k', desc: 'Jump always to k' },
    ],
    'Return Instructions': [
      { op: '0x06', name: 'ret #k', desc: 'Return k bytes (0 = reject, >0 = accept)' },
    ],
    'Common Values': [
      { op: '0x0800', name: 'IPv4', desc: 'EtherType for IPv4' },
      { op: '0x86dd', name: 'IPv6', desc: 'EtherType for IPv6' },
      { op: '0x06', name: 'TCP', desc: 'IP Protocol number for TCP' },
      { op: '0x11', name: 'UDP', desc: 'IP Protocol number for UDP' },
      { op: '0x01', name: 'ICMP', desc: 'IP Protocol number for ICMP' },
    ],
  }

  return (
    <div className="mt-4 bg-gray-800 rounded-lg p-6">
      <h3 className="text-lg font-semibold mb-4">BPF Opcode Reference</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Object.entries(opcodes).map(([category, ops]) => (
          <div key={category}>
            <h4 className="text-sm font-medium text-gray-400 mb-2">{category}</h4>
            <table className="w-full text-sm">
              <tbody>
                {ops.map((op, i) => (
                  <tr key={i} className="border-b border-gray-700/50">
                    <td className="py-1 font-mono text-blue-400 w-20">{op.op}</td>
                    <td className="py-1 font-mono text-green-400 w-32">{op.name}</td>
                    <td className="py-1 text-gray-400">{op.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    </div>
  )
}

// Metric Card Component
function MetricCard({ 
  label, 
  value, 
  color = 'blue' 
}: { 
  label: string
  value: string | number
  color?: 'blue' | 'green' | 'yellow' | 'purple'
}) {
  const colorClasses = {
    blue: 'text-blue-400',
    green: 'text-green-400',
    yellow: 'text-yellow-400',
    purple: 'text-purple-400'
  }

  return (
    <div className="bg-gray-900/50 rounded-lg p-3">
      <div className="text-xs text-gray-400 mb-1">{label}</div>
      <div className={`text-xl font-bold ${colorClasses[color]}`}>{value}</div>
    </div>
  )
}
