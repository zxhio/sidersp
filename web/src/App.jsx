import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import OverviewPage from './pages/OverviewPage'
import StatusPage from './pages/StatusPage'
import RulesPage from './pages/RulesPage'
import EventsPage from './pages/EventsPage'
import ResponseResultsPage from './pages/ResponseResultsPage'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/status" element={<StatusPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/response-results" element={<ResponseResultsPage />} />
      </Routes>
    </Layout>
  )
}
