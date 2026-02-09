import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Packets from './pages/Packets'
import Topology from './pages/Topology'
import Alerts from './pages/Alerts'
import BPFCompare from './pages/BPFCompare'
import Layout from './components/Layout'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="packets" element={<Packets />} />
          <Route path="topology" element={<Topology />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="bpf" element={<BPFCompare />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
