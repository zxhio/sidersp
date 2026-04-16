import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import OverviewPage from './pages/OverviewPage'
import StatusPage from './pages/StatusPage'
import RulesPage from './pages/RulesPage'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/status" element={<StatusPage />} />
      </Routes>
    </Layout>
  )
}
