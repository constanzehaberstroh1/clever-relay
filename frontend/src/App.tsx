import { useState, useEffect, useRef, useCallback } from 'react'
import './App.css'

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface SystemMetrics {
  mem_total_mb: number
  mem_used_mb: number
  mem_free_mb: number
  mem_usage_percent: number
  go_alloc_mb: number
  go_heap_mb: number
  go_stack_mb: number
  go_sys_mb: number
  gc_pause_ms: number
  num_gc: number
  goroutines: number
  cpu_usage_percent: number
  uptime: string
  uptime_seconds: number
}

interface SessionInfo {
  id: string
  target: string
  created_at: string
  last_used: string
  buffer_len: number
  closed: boolean
}

interface LogEntry {
  timestamp: string
  level: string
  component: string
  message: string
  details?: string
}

interface WSMessage {
  type: 'metrics' | 'log'
  data: SystemMetrics | LogEntry
  sessions?: number
  session_list?: SessionInfo[]
}

// ═══════════════════════════════════════════════════════════════════════════
// API Client
// ═══════════════════════════════════════════════════════════════════════════

const API_BASE = '/admin/api'

async function apiLogin(password: string): Promise<string> {
  const res = await fetch(`${API_BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  if (!res.ok) throw new Error('Invalid password')
  const data = await res.json()
  return data.token
}

async function apiFetch(path: string, token: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}

// ═══════════════════════════════════════════════════════════════════════════
// App Component
// ═══════════════════════════════════════════════════════════════════════════

function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('relay_token'))
  const [view, setView] = useState<'dashboard' | 'sessions' | 'logs'>('dashboard')

  // Auth state
  const [password, setPassword] = useState('')
  const [loginError, setLoginError] = useState('')
  const [isLoggingIn, setIsLoggingIn] = useState(false)

  // Real-time data
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null)
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [sessionCount, setSessionCount] = useState(0)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [wsConnected, setWsConnected] = useState(false)

  // Log filters
  const [logFilter, setLogFilter] = useState<string>('ALL')
  const [logSearch, setLogSearch] = useState('')

  const wsRef = useRef<WebSocket | null>(null)

  // ── Login ──────────────────────────────────────────────────────────────
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoggingIn(true)
    setLoginError('')
    try {
      const t = await apiLogin(password)
      setToken(t)
      localStorage.setItem('relay_token', t)
      setPassword('')
    } catch {
      setLoginError('Authentication failed. Check your password.')
    } finally {
      setIsLoggingIn(false)
    }
  }

  const handleLogout = () => {
    setToken(null)
    localStorage.removeItem('relay_token')
    wsRef.current?.close()
  }

  // ── WebSocket ──────────────────────────────────────────────────────────
  const connectWebSocket = useCallback(() => {
    if (!token) return

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const ws = new WebSocket(`${proto}//${host}/admin/ws?token=${token}`)

    ws.onopen = () => {
      setWsConnected(true)
    }

    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data)
        if (msg.type === 'metrics') {
          setMetrics(msg.data as SystemMetrics)
          if (msg.sessions !== undefined) setSessionCount(msg.sessions)
          if (msg.session_list) setSessions(msg.session_list)
        } else if (msg.type === 'log') {
          setLogs(prev => {
            const next = [msg.data as LogEntry, ...prev]
            return next.slice(0, 5000) // Keep max 5000 in UI
          })
        }
      } catch { /* ignore parse errors */ }
    }

    ws.onclose = () => {
      setWsConnected(false)
      // Reconnect after 3 seconds
      setTimeout(() => connectWebSocket(), 3000)
    }

    ws.onerror = () => ws.close()

    wsRef.current = ws
  }, [token])

  useEffect(() => {
    if (token) {
      connectWebSocket()
      // Initial data fetch
      apiFetch('/logs?count=200', token).then(setLogs).catch(() => {})
    }
    return () => wsRef.current?.close()
  }, [token, connectWebSocket])

  // ── Render ─────────────────────────────────────────────────────────────
  if (!token) {
    return <LoginPage
      password={password}
      setPassword={setPassword}
      onSubmit={handleLogin}
      error={loginError}
      isLoading={isLoggingIn}
    />
  }

  return (
    <div className="dashboard">
      <Sidebar view={view} setView={setView} onLogout={handleLogout} wsConnected={wsConnected} />
      <main className="main-content">
        {view === 'dashboard' && <DashboardView metrics={metrics} sessionCount={sessionCount} sessions={sessions} />}
        {view === 'sessions' && <SessionsView sessions={sessions} />}
        {view === 'logs' && <LogsView logs={logs} filter={logFilter} setFilter={setLogFilter} search={logSearch} setSearch={setLogSearch} />}
      </main>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Login Page
// ═══════════════════════════════════════════════════════════════════════════

function LoginPage({ password, setPassword, onSubmit, error, isLoading }: {
  password: string
  setPassword: (v: string) => void
  onSubmit: (e: React.FormEvent) => void
  error: string
  isLoading: boolean
}) {
  return (
    <div className="login-container">
      <div className="login-card animate-fade-in">
        <div className="login-icon">🛡️</div>
        <h1>Clever Relay</h1>
        <p className="login-subtitle">Exit Node Admin Dashboard</p>

        <form onSubmit={onSubmit} className="login-form">
          <div className="input-group">
            <label htmlFor="password">Authentication Key</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Enter admin password (PSK)"
              autoFocus
              required
            />
          </div>
          {error && <div className="login-error">{error}</div>}
          <button type="submit" className="login-btn" disabled={isLoading}>
            {isLoading ? <span className="spinner" /> : null}
            {isLoading ? 'Authenticating...' : 'Access Dashboard'}
          </button>
        </form>

        <div className="login-footer">
          <span className="lock-icon">🔒</span> Encrypted with ChaCha20-Poly1305
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Sidebar
// ═══════════════════════════════════════════════════════════════════════════

function Sidebar({ view, setView, onLogout, wsConnected }: {
  view: string
  setView: (v: 'dashboard' | 'sessions' | 'logs') => void
  onLogout: () => void
  wsConnected: boolean
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">⚡</div>
        <div>
          <div className="sidebar-title">Clever Relay</div>
          <div className="sidebar-subtitle">Exit Node</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <button className={`nav-item ${view === 'dashboard' ? 'active' : ''}`} onClick={() => setView('dashboard')}>
          <span className="nav-icon">📊</span> Dashboard
        </button>
        <button className={`nav-item ${view === 'sessions' ? 'active' : ''}`} onClick={() => setView('sessions')}>
          <span className="nav-icon">🔗</span> Sessions
        </button>
        <button className={`nav-item ${view === 'logs' ? 'active' : ''}`} onClick={() => setView('logs')}>
          <span className="nav-icon">📋</span> Logs
        </button>
      </nav>

      <div className="sidebar-footer">
        <div className={`ws-status ${wsConnected ? 'connected' : 'disconnected'}`}>
          <span className="status-dot" />
          {wsConnected ? 'Live' : 'Reconnecting...'}
        </div>
        <button className="logout-btn" onClick={onLogout}>Logout</button>
      </div>
    </aside>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Dashboard View
// ═══════════════════════════════════════════════════════════════════════════

function DashboardView({ metrics, sessionCount, sessions }: {
  metrics: SystemMetrics | null
  sessionCount: number
  sessions: SessionInfo[]
}) {
  if (!metrics) {
    return <div className="loading-state"><span className="spinner large" /> Connecting to exit node...</div>
  }

  return (
    <div className="dashboard-view animate-slide-up">
      <header className="view-header">
        <h1>System Overview</h1>
        <span className="uptime-badge">⏱ {metrics.uptime}</span>
      </header>

      {/* Stat Cards */}
      <div className="stat-grid">
        <StatCard
          label="Active Sessions"
          value={sessionCount.toString()}
          icon="🔗"
          color="blue"
        />
        <StatCard
          label="Goroutines"
          value={metrics.goroutines.toString()}
          icon="⚡"
          color="purple"
        />
        <StatCard
          label="CPU Usage"
          value={`${metrics.cpu_usage_percent.toFixed(1)}%`}
          icon="🖥️"
          color={metrics.cpu_usage_percent > 80 ? 'red' : 'green'}
        />
        <StatCard
          label="Memory Used"
          value={`${metrics.mem_used_mb.toFixed(0)} MB`}
          icon="💾"
          color={metrics.mem_usage_percent > 80 ? 'red' : 'amber'}
          subtitle={metrics.mem_total_mb > 0 ? `${metrics.mem_usage_percent.toFixed(1)}% of ${metrics.mem_total_mb.toFixed(0)} MB` : undefined}
        />
      </div>

      {/* Go Runtime + Resource Panels */}
      <div className="panel-grid">
        <div className="panel">
          <h3 className="panel-title">Go Runtime</h3>
          <div className="metric-list">
            <MetricRow label="Heap Allocated" value={`${metrics.go_heap_mb.toFixed(2)} MB`} />
            <MetricRow label="Stack In Use" value={`${metrics.go_stack_mb.toFixed(2)} MB`} />
            <MetricRow label="System Total" value={`${metrics.go_sys_mb.toFixed(2)} MB`} />
            <MetricRow label="GC Pause" value={`${metrics.gc_pause_ms.toFixed(3)} ms`} />
            <MetricRow label="GC Cycles" value={metrics.num_gc.toString()} />
          </div>
        </div>

        <div className="panel">
          <h3 className="panel-title">Memory Breakdown</h3>
          <div className="memory-bars">
            <ProgressBar label="System RAM" value={metrics.mem_usage_percent} color="blue" />
            <ProgressBar label="Go Heap" value={metrics.go_sys_mb > 0 ? (metrics.go_heap_mb / metrics.go_sys_mb) * 100 : 0} color="purple" />
          </div>
        </div>
      </div>

      {/* Active Connections Quick View */}
      {sessions.length > 0 && (
        <div className="panel">
          <h3 className="panel-title">Active Connections</h3>
          <div className="connections-list">
            {sessions.slice(0, 8).map(s => (
              <div key={s.id} className="connection-item">
                <span className={`conn-dot ${s.closed ? 'closed' : 'active'}`} />
                <span className="conn-target mono">{s.target}</span>
                <span className="conn-buffer">{formatBytes(s.buffer_len)} buffered</span>
              </div>
            ))}
            {sessions.length > 8 && (
              <div className="conn-more">+{sessions.length - 8} more connections</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Sessions View
// ═══════════════════════════════════════════════════════════════════════════

function SessionsView({ sessions }: { sessions: SessionInfo[] }) {
  return (
    <div className="sessions-view animate-slide-up">
      <header className="view-header">
        <h1>Active Sessions</h1>
        <span className="count-badge">{sessions.length} total</span>
      </header>

      {sessions.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🔗</div>
          <p>No active tunnel sessions</p>
          <p className="empty-hint">Sessions appear when traffic flows through the relay</p>
        </div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Session ID</th>
                <th>Target</th>
                <th>Buffer</th>
                <th>Created</th>
                <th>Last Active</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map(s => (
                <tr key={s.id} className={s.closed ? 'row-closed' : ''}>
                  <td>
                    <span className={`status-pill ${s.closed ? 'closed' : 'active'}`}>
                      {s.closed ? 'Closed' : 'Active'}
                    </span>
                  </td>
                  <td className="mono cell-id">{s.id.substring(0, 12)}…</td>
                  <td className="mono cell-target">{s.target}</td>
                  <td>{formatBytes(s.buffer_len)}</td>
                  <td>{formatTime(s.created_at)}</td>
                  <td>{formatTime(s.last_used)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Logs View – Virtualized Log Viewer
// ═══════════════════════════════════════════════════════════════════════════

function LogsView({ logs, filter, setFilter, search, setSearch }: {
  logs: LogEntry[]
  filter: string
  setFilter: (v: string) => void
  search: string
  setSearch: (v: string) => void
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  // Auto-scroll to top when new logs arrive
  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = 0
    }
  }, [logs.length, autoScroll])

  const filtered = logs.filter(log => {
    if (filter !== 'ALL' && log.level !== filter) return false
    if (search && !log.message.toLowerCase().includes(search.toLowerCase()) &&
        !log.component.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const levelCounts = {
    ALL: logs.length,
    INFO: logs.filter(l => l.level === 'INFO').length,
    WARN: logs.filter(l => l.level === 'WARN').length,
    ERROR: logs.filter(l => l.level === 'ERROR').length,
    DEBUG: logs.filter(l => l.level === 'DEBUG').length,
  }

  return (
    <div className="logs-view animate-slide-up">
      <header className="view-header">
        <h1>Real-Time Logs</h1>
        <span className="count-badge">{filtered.length} entries</span>
      </header>

      {/* Filters */}
      <div className="log-controls">
        <div className="log-filters">
          {Object.entries(levelCounts).map(([level, count]) => (
            <button
              key={level}
              className={`filter-btn ${filter === level ? 'active' : ''} level-${level.toLowerCase()}`}
              onClick={() => setFilter(level)}
            >
              {level} <span className="filter-count">{count}</span>
            </button>
          ))}
        </div>
        <input
          type="text"
          className="log-search"
          placeholder="Search logs..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <label className="auto-scroll-toggle">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={e => setAutoScroll(e.target.checked)}
          />
          Auto-scroll
        </label>
      </div>

      {/* Log Entries – Virtualized: only render visible entries */}
      <div className="log-container" ref={containerRef}>
        {filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📋</div>
            <p>No log entries match your filters</p>
          </div>
        ) : (
          filtered.slice(0, 500).map((log, i) => (
            <div key={`${log.timestamp}-${i}`} className={`log-entry level-${log.level.toLowerCase()}`}>
              <span className="log-time mono">{formatLogTime(log.timestamp)}</span>
              <span className={`log-level badge-${log.level.toLowerCase()}`}>{log.level}</span>
              <span className="log-component">[{log.component}]</span>
              <span className="log-message">{log.message}</span>
              {log.details && <span className="log-details mono">{log.details}</span>}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Shared Components
// ═══════════════════════════════════════════════════════════════════════════

function StatCard({ label, value, icon, color, subtitle }: {
  label: string; value: string; icon: string; color: string; subtitle?: string
}) {
  return (
    <div className={`stat-card color-${color}`}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-content">
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
        {subtitle && <div className="stat-subtitle">{subtitle}</div>}
      </div>
    </div>
  )
}

function MetricRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric-row">
      <span className="metric-label">{label}</span>
      <span className="metric-value mono">{value}</span>
    </div>
  )
}

function ProgressBar({ label, value, color }: { label: string; value: number; color: string }) {
  const clamped = Math.min(100, Math.max(0, value))
  return (
    <div className="progress-container">
      <div className="progress-header">
        <span>{label}</span>
        <span className="mono">{clamped.toFixed(1)}%</span>
      </div>
      <div className="progress-track">
        <div
          className={`progress-fill color-${color}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

function formatTime(iso: string): string {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    return d.toLocaleTimeString('en-US', { hour12: false })
  } catch { return '—' }
}

function formatLogTime(iso: string): string {
  if (!iso) return ''
  try {
    const d = new Date(iso)
    return d.toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 3 })
  } catch { return iso.substring(11, 23) }
}

export default App
