import { useState, useEffect, useRef, useCallback } from 'react'
import { useStore } from './store'
import type { LogEntry } from './store'

// ═══════════════════════════════════════════════════════════════════════════
// SVG Icons (inline to avoid external deps)
// ═══════════════════════════════════════════════════════════════════════════

const Icons = {
  dashboard: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>,
  nodes: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v4m0 12v4M2 12h4m12 0h4M4.93 4.93l2.83 2.83m8.49 8.49l2.83 2.83M4.93 19.07l2.83-2.83m8.49-8.49l2.83-2.83"/></svg>,
  config: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.73 12.73l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>,
  logs: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>,
  close: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
  plus: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  trash: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>,
}

type Page = 'dashboard' | 'nodes' | 'config'

// ═══════════════════════════════════════════════════════════════════════════
// App
// ═══════════════════════════════════════════════════════════════════════════

export default function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const [logOpen, setLogOpen] = useState(false)
  const { connectWS, errorCount, logs, wsConnected } = useStore()

  useEffect(() => { connectWS() }, [])

  const hasErrors = errorCount > 0

  return (
    <div className="app-layout">
      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-brand-icon">🛡️</div>
          <div>
            <h1>Clever Relay</h1>
            <small>Client Panel</small>
          </div>
        </div>
        <nav className="sidebar-nav">
          <button className={`nav-item ${page === 'dashboard' ? 'active' : ''}`} onClick={() => setPage('dashboard')}>
            {Icons.dashboard} <span>Dashboard</span>
          </button>
          <button className={`nav-item ${page === 'nodes' ? 'active' : ''}`} onClick={() => setPage('nodes')}>
            {Icons.nodes} <span>GAS Nodes</span>
          </button>
          <button className={`nav-item ${page === 'config' ? 'active' : ''}`} onClick={() => setPage('config')}>
            {Icons.config} <span>Configuration</span>
          </button>
        </nav>
        <div style={{ padding: '0 24px' }}>
          <div className="card" style={{ padding: '12px 16px', fontSize: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className={`status-dot ${wsConnected ? 'online' : 'offline'}`}></span>
              <span style={{ color: 'var(--text-secondary)' }}>
                {wsConnected ? 'Live Stream' : 'Disconnected'}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main Content ──────────────────────────────────────────────── */}
      <main className="main-content">
        {page === 'dashboard' && <DashboardPage />}
        {page === 'nodes' && <NodesPage />}
        {page === 'config' && <ConfigPage />}
      </main>

      {/* ── Floating Log Button ───────────────────────────────────────── */}
      <button
        className={`log-fab ${hasErrors ? 'has-errors' : ''}`}
        onClick={() => setLogOpen(true)}
        title="View live logs"
      >
        {Icons.logs}
        {errorCount > 0 && <span className="badge">{errorCount > 99 ? '99+' : errorCount}</span>}
      </button>

      {/* ── Log Drawer ────────────────────────────────────────────────── */}
      {logOpen && <LogDrawer logs={logs} onClose={() => setLogOpen(false)} />}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Dashboard Page
// ═══════════════════════════════════════════════════════════════════════════

function DashboardPage() {
  const { status, fetchStatus, fetchNodes, nodes } = useStore()

  useEffect(() => {
    fetchStatus()
    fetchNodes()
    const interval = setInterval(fetchStatus, 3000)
    return () => clearInterval(interval)
  }, [])

  const healthyNodes = nodes.filter(n => n.state === 'healthy').length

  return (
    <>
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>Real-time overview of the Clever Relay local engine</p>
      </div>

      <div className="card-grid">
        <div className="card stat-card">
          <span className="stat-label">SOCKS5 Status</span>
          <span className={`stat-value ${status?.socks5_active ? 'green' : ''}`}>
            {status?.socks5_active ? '● Online' : '○ Offline'}
          </span>
          <span className="stat-sub">{status?.socks5_addr || ':1080'}</span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">Active Sessions</span>
          <span className="stat-value blue">{status?.active_sessions ?? 0}</span>
          <span className="stat-sub">TCP connections</span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">GAS Nodes</span>
          <span className="stat-value purple">{healthyNodes}/{nodes.length}</span>
          <span className="stat-sub">healthy / total</span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">Uptime</span>
          <span className="stat-value" style={{ fontSize: '22px' }}>
            {status?.uptime_human ?? '–'}
          </span>
          <span className="stat-sub">since start</span>
        </div>
      </div>

      <div className="card-grid">
        <div className="card stat-card">
          <span className="stat-label">Memory Usage</span>
          <span className="stat-value yellow">
            {status?.memory?.alloc_mb?.toFixed(1) ?? '–'} MB
          </span>
          <span className="stat-sub">
            Sys: {status?.memory?.sys_mb?.toFixed(1) ?? '–'} MB · GC: {status?.memory?.gc_cycles ?? 0}
          </span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">Goroutines</span>
          <span className="stat-value blue">{status?.goroutines ?? 0}</span>
          <span className="stat-sub">active threads</span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">Logs Processed</span>
          <span className="stat-value purple">{status?.logger?.total ?? 0}</span>
          <span className="stat-sub">
            Dropped: {status?.logger?.dropped ?? 0} · Buffered: {status?.logger?.buffered ?? 0}
          </span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">Version</span>
          <span className="stat-value" style={{ fontSize: '16px', color: 'var(--text-secondary)' }}>
            {status?.version ?? 'dev'}
          </span>
          <span className="stat-sub">{status?.build_time ?? 'unknown'}</span>
        </div>
      </div>
    </>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Nodes Page
// ═══════════════════════════════════════════════════════════════════════════

function NodesPage() {
  const { nodes, fetchNodes, addNode, removeNode, toggleNode, nodesLoading } = useStore()
  const [newUrl, setNewUrl] = useState('')

  useEffect(() => { fetchNodes() }, [])

  const handleAdd = async () => {
    if (!newUrl.trim()) return
    try {
      await addNode(newUrl.trim())
      setNewUrl('')
    } catch (e) {
      alert('Failed to add node: ' + (e as Error).message)
    }
  }

  return (
    <>
      <div className="page-header">
        <h2>GAS Nodes</h2>
        <p>Manage Google Apps Script relay endpoints</p>
      </div>

      <div className="input-group">
        <input
          className="input"
          placeholder="https://script.google.com/macros/s/DEPLOYMENT_ID/exec"
          value={newUrl}
          onChange={e => setNewUrl(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
        />
        <button className="btn btn-primary" onClick={handleAdd}>
          {Icons.plus} Add Node
        </button>
      </div>

      <div className="node-list">
        {nodes.length === 0 && !nodesLoading && (
          <div className="card" style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
            No GAS nodes configured. Add one above.
          </div>
        )}
        {nodes.map((node, i) => (
          <div className="node-item" key={i}>
            <span className="node-url">{node.url}</span>
            <div className="node-meta">
              <span className="node-latency">{node.avg_latency_ms.toFixed(0)}ms</span>
              <span className={`node-badge ${node.state === 'healthy' ? 'healthy' : node.state.includes('24h') ? 'disabled' : 'cooldown'}`}>
                {node.state === 'healthy' ? 'Healthy' : node.state === 'cooldown_5m' ? 'Cooldown' : 'Disabled'}
              </span>
              <span className="stat-sub" style={{ minWidth: '60px', textAlign: 'right' }}>
                ✓{node.successes} ✗{node.failures}
              </span>
              <div
                className={`toggle ${node.state === 'healthy' ? 'active' : ''}`}
                onClick={() => toggleNode(node.url, node.state === 'healthy' ? 'disable' : 'enable')}
                title={node.state === 'healthy' ? 'Disable' : 'Enable'}
              />
              <button className="btn btn-danger btn-sm" onClick={() => { if (confirm('Remove this node?')) removeNode(node.url) }}>
                {Icons.trash}
              </button>
            </div>
          </div>
        ))}
      </div>
    </>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Config Page
// ═══════════════════════════════════════════════════════════════════════════

function ConfigPage() {
  const { config, fetchConfig, updateConfig } = useStore()
  const [local, setLocal] = useState<Record<string, number | string>>({})

  useEffect(() => { fetchConfig() }, [])
  useEffect(() => {
    if (config) setLocal({ ...config })
  }, [config])

  const handleSave = () => {
    updateConfig(local as any)
  }

  const fields = [
    { key: 'chunk_size', label: 'Chunk Size (bytes)', type: 'number' },
    { key: 'flush_ms', label: 'Flush Interval (ms)', type: 'number' },
    { key: 'max_retries', label: 'Max Retries', type: 'number' },
    { key: 'timeout_seconds', label: 'Timeout (seconds)', type: 'number' },
    { key: 'parallel_pulls', label: 'Parallel PULLs', type: 'number' },
  ]

  return (
    <>
      <div className="page-header">
        <h2>Configuration</h2>
        <p>Adjust engine parameters at runtime without restarting</p>
      </div>

      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="config-grid">
          {fields.map(f => (
            <div className="config-field" key={f.key}>
              <label>{f.label}</label>
              <input
                type={f.type}
                value={local[f.key] ?? ''}
                onChange={e => setLocal({ ...local, [f.key]: f.type === 'number' ? parseInt(e.target.value) || 0 : e.target.value })}
              />
            </div>
          ))}
        </div>
        <div style={{ marginTop: '24px', display: 'flex', gap: '12px' }}>
          <button className="btn btn-primary" onClick={handleSave}>Save Changes</button>
          <button className="btn btn-secondary" onClick={() => config && setLocal({ ...config })}>Reset</button>
        </div>
      </div>
    </>
  )
}

// ═══════════════════════════════════════════════════════════════════════════
// Log Drawer (Floating Real-time Log Viewer)
// ═══════════════════════════════════════════════════════════════════════════

function LogDrawer({ logs, onClose }: { logs: LogEntry[]; onClose: () => void }) {
  const listRef = useRef<HTMLDivElement>(null)
  const { clearLogs } = useStore()
  const [autoScroll, setAutoScroll] = useState(true)

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight
    }
  }, [logs.length, autoScroll])

  const handleScroll = useCallback(() => {
    if (!listRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = listRef.current
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 40)
  }, [])

  const formatTime = (ts: string) => {
    try {
      const d = new Date(ts)
      return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
        + '.' + String(d.getMilliseconds()).padStart(3, '0')
    } catch {
      return ts
    }
  }

  return (
    <>
      <div className="log-drawer-overlay" onClick={onClose} />
      <div className="log-drawer">
        <div className="log-drawer-header">
          <h3>📋 Live Logs ({logs.length})</h3>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="btn btn-secondary btn-sm" onClick={clearLogs}>Clear</button>
            <button className="log-drawer-close" onClick={onClose}>{Icons.close}</button>
          </div>
        </div>
        <div className="log-list" ref={listRef} onScroll={handleScroll}>
          {logs.length === 0 && (
            <div style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
              Waiting for logs...
            </div>
          )}
          {logs.map((entry, i) => (
            <div className="log-entry" key={i}>
              <span className="log-time">{formatTime(entry.timestamp)}</span>
              <span className={`log-level ${entry.level}`}>{entry.level}</span>
              <span className="log-component">[{entry.component}]</span>
              <span className="log-message">{entry.message}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
