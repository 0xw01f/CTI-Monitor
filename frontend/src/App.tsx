import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import TopBar from './components/TopBar'
import Dashboard from './pages/Dashboard'
import Threats from './pages/Threats'
import Actors from './pages/Actors'
import Alerts from './pages/Alerts'
import Settings from './pages/Settings'
import ThreatMap from './pages/ThreatMap'
import AdminLogin from './pages/AdminLogin'
import { getAdminMe } from './api/client'
import { clearAdminToken, getAdminToken, isAdminAuthenticated } from './lib/adminAuth'

function PublicShell() {
  const [search, setSearch] = useState('')

  return (
    <div className="h-screen bg-[#080810] text-slate-200 flex overflow-hidden">
      <Sidebar mode="public" />
      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar search={search} onSearch={setSearch} allowRefresh={false} />
        <main className="flex-1 overflow-auto p-4">
          <Routes>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/threats" element={<Threats search={search} readOnly />} />
            <Route path="/actors" element={<Actors />} />
            <Route path="/map" element={<ThreatMap />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

function AdminShell() {
  const [search, setSearch] = useState('')
  const [checking, setChecking] = useState(true)
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    const verify = async () => {
      if (!isAdminAuthenticated()) {
        navigate('/admin/login', { replace: true, state: { from: location.pathname } })
        return
      }
      try {
        await getAdminMe()
      } catch {
        clearAdminToken()
        navigate('/admin/login', { replace: true, state: { from: location.pathname } })
        return
      }
      setChecking(false)
    }
    verify()
  }, [location.pathname, navigate])

  if (checking) {
    return (
      <div className="h-screen bg-[#080810] text-slate-200 grid place-items-center">
        <p className="text-xs text-slate-500">Checking admin session...</p>
      </div>
    )
  }

  return (
    <div className="h-screen bg-[#080810] text-slate-200 flex overflow-hidden">
      <Sidebar
        mode="admin"
        onLogout={() => {
          clearAdminToken()
          navigate('/admin/login', { replace: true })
        }}
      />
      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar search={search} onSearch={setSearch} allowRefresh />
        <main className="flex-1 overflow-auto p-4">
          <Routes>
            <Route path="/admin/dashboard" element={<Dashboard />} />
            <Route path="/admin/threats" element={<Threats search={search} />} />
            <Route path="/admin/actors" element={<Actors />} />
            <Route path="/admin/map" element={<ThreatMap />} />
            <Route path="/admin/alerts" element={<Alerts />} />
            <Route path="/admin/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/admin/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

function RootRouter() {
  const location = useLocation()

  if (location.pathname.startsWith('/admin')) {
    if (location.pathname === '/admin/login') return <AdminLogin />
    // Fast path for first paint; full validation is done inside AdminShell.
    if (!getAdminToken()) return <Navigate to="/admin/login" replace state={{ from: location.pathname }} />
    return <AdminShell />
  }
  return <PublicShell />
}

export default function App() {
  return (
    <BrowserRouter>
      <RootRouter />
    </BrowserRouter>
  )
}
