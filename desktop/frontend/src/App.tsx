import { useState, useEffect, useRef } from 'react';
import './App.css';
import {
  GetNodes,
  AddNode,
  DeleteNode,
  ToggleNodeStatus,
  TestNode,
  GetSettings,
  SaveSettings,
  StartProxy,
  StopProxy,
  GetProxyStatus
} from "../wailsjs/go/main/App";

// ═══════════════════════════════════════════════════════════════════════════
// TypeScript Interfaces
// ═══════════════════════════════════════════════════════════════════════════

interface GASNode {
  id: string;
  url: string;
  status: string;
  total_requests_sent: number;
  failed_requests: number;
  average_latency_ms: number;
  last_checked_at: string;
}

interface Settings {
  socks_addr: string;
  psk: string;
  google_client_id: string;
  google_client_secret: string;
  google_refresh_token: string;
}

interface ProxyStatus {
  status: string;
  socks_addr: string;
  psk_configured: boolean;
  active_node_count: number;
  gcloud_metrics: {
    active_executions: number;
    daily_requests_used: number;
    daily_requests_max: number;
    error_count_5xx: number;
    rate_limit_hits: number;
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════════════════════

function App() {
  const [view, setView] = useState<'overview' | 'nodes' | 'settings'>('overview');

  // State bindings
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [nodes, setNodes] = useState<GASNode[]>([]);
  const [settings, setSettings] = useState<Settings>({
    socks_addr: ':1080',
    psk: '',
    google_client_id: '',
    google_client_secret: '',
    google_refresh_token: '',
  });

  // Action states
  const [newNodeUrl, setNewNodeUrl] = useState('');
  const [testingNodeId, setTestingNodeId] = useState<string | null>(null);
  const [alert, setAlert] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Settings inputs
  const [socksAddrInput, setSocksAddrInput] = useState('');
  const [pskInput, setPskInput] = useState('');
  const [clientIDInput, setClientIDInput] = useState('');
  const [clientSecretInput, setClientSecretInput] = useState('');
  const [refreshTokenInput, setRefreshTokenInput] = useState('');

  // ── Refresh Status & Nodes ──────────────────────────────────────────────
  const refreshAll = async () => {
    try {
      const currentStatus = await GetProxyStatus() as any;
      setStatus(currentStatus);

      const currentNodes = await GetNodes() as any[];
      setNodes(currentNodes);
    } catch (err) {
      console.error("Refresh error:", err);
    }
  };

  useEffect(() => {
    refreshAll();
    // Fetch settings once
    GetSettings().then((s: any) => {
      setSettings(s);
      setSocksAddrInput(s.socks_addr);
      setPskInput(s.psk);
      setClientIDInput(s.google_client_id);
      setClientSecretInput(s.google_client_secret);
      setRefreshTokenInput(s.google_refresh_token);
    });

    // Periodically fetch proxy status
    const timer = setInterval(() => {
      refreshAll();
    }, 2000);

    return () => clearInterval(timer);
  }, []);

  // ── SOCKS5 Toggler ──────────────────────────────────────────────────────
  const toggleProxy = async () => {
    if (!status) return;

    try {
      if (status.status === 'Running') {
        await StopProxy();
        setAlert({ type: 'success', message: 'SOCKS5 Proxy stopped successfully' });
      } else {
        await StartProxy();
        setAlert({ type: 'success', message: `SOCKS5 Proxy started successfully on ${status.socks_addr}` });
      }
      refreshAll();
    } catch (err: any) {
      setAlert({ type: 'error', message: err.toString() });
    }
  };

  // ── Node Actions ────────────────────────────────────────────────────────
  const handleAddNode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNodeUrl) return;

    try {
      await AddNode(newNodeUrl);
      setNewNodeUrl('');
      setAlert({ type: 'success', message: 'Google Apps Script URL added to the pool' });
      refreshAll();
    } catch (err: any) {
      setAlert({ type: 'error', message: err.toString() });
    }
  };

  const handleDeleteNode = async (id: string) => {
    try {
      await DeleteNode(id);
      setAlert({ type: 'success', message: 'Node deleted successfully' });
      refreshAll();
    } catch (err: any) {
      setAlert({ type: 'error', message: err.toString() });
    }
  };

  const handleToggleNode = async (id: string, currentStatus: string) => {
    const nextStatus = currentStatus === 'Active' ? 'Paused' : 'Active';
    try {
      await ToggleNodeStatus(id, nextStatus);
      refreshAll();
    } catch (err: any) {
      setAlert({ type: 'error', message: err.toString() });
    }
  };

  const handleTestNode = async (id: string) => {
    setTestingNodeId(id);
    try {
      const res = await TestNode(id) as any;
      if (res.is_valid) {
        setAlert({ type: 'success', message: `Node validated successfully! Latency: ${res.latency / 1000000} ms` });
      } else {
        setAlert({ type: 'error', message: `Node validation failed: ${res.error}` });
      }
      refreshAll();
    } catch (err: any) {
      setAlert({ type: 'error', message: err.toString() });
    } finally {
      setTestingNodeId(null);
    }
  };

  // ── Settings Save ───────────────────────────────────────────────────────
  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await SaveSettings(
        socksAddrInput,
        pskInput,
        clientIDInput,
        clientSecretInput,
        refreshTokenInput
      );
      setAlert({ type: 'success', message: 'Settings saved successfully. SOCKS5 will reload on next startup.' });
      refreshAll();
    } catch (err: any) {
      setAlert({ type: 'error', message: err.toString() });
    }
  };

  // Auto dismiss alert after 5s
  useEffect(() => {
    if (alert) {
      const t = setTimeout(() => setAlert(null), 5000);
      return () => clearTimeout(t);
    }
  }, [alert]);

  const activeCount = nodes.filter(n => n.status === 'Active').length;
  const totalRequests = status?.gcloud_metrics.daily_requests_used || 0;
  const maxRequests = status?.gcloud_metrics.daily_requests_max || 20000;
  const quotaPercent = Math.min(100, Math.max(0, maxRequests > 0 ? (totalRequests / maxRequests) * 100 : 0));

  return (
    <div className="app-layout">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <span className="logo-shield">🛡️</span>
          <div className="logo-text">
            <h1>Clever Relay</h1>
            <p>Local Client</p>
          </div>
        </div>

        <nav className="nav-menu">
          <button className={`nav-button ${view === 'overview' ? 'active' : ''}`} onClick={() => setView('overview')}>
            <span>📊</span> Overview
          </button>
          <button className={`nav-button ${view === 'nodes' ? 'active' : ''}`} onClick={() => setView('nodes')}>
            <span>🔗</span> GAS Pool ({activeCount}/{nodes.length})
          </button>
          <button className={`nav-button ${view === 'settings' ? 'active' : ''}`} onClick={() => setView('settings')}>
            <span>⚙️</span> Settings
          </button>
        </nav>

        <div className="sidebar-footer">
          <span className="version-info">Client v1.2.0 (GORM)</span>
        </div>
      </aside>

      {/* Main Workspace */}
      <main className="workspace">
        {alert && (
          <div className={`alert-message ${alert.type}`}>
            {alert.message}
          </div>
        )}

        {view === 'overview' && (
          <div className="view-container">
            <header className="view-header">
              <h1>Client Overview</h1>
              <p>Start SOCKS5 proxy server and view smart pool traffic metrics</p>
            </header>

            <div className="overview-grid">
              {/* Power Section */}
              <div className="power-section">
                <div
                  className={`ring-outer ${status?.status === 'Running' ? 'running' : 'stopped'}`}
                  onClick={toggleProxy}
                >
                  <button className="power-btn">
                    {status?.status === 'Running' ? '⚡' : '🔌'}
                  </button>
                </div>
                <div className="status-label">Proxy Server</div>
                <div className={`status-value ${status?.status === 'Running' ? 'running' : 'stopped'}`}>
                  {status?.status === 'Running' ? 'CONNECTED' : 'DISCONNECTED'}
                </div>
                {status?.status === 'Running' && (
                  <div className="proxy-addr">
                    SOCKS5: socks5://127.0.0.1{status.socks_addr}
                  </div>
                )}
              </div>

              {/* Metrics Section */}
              <div className="metrics-section">
                {/* Quota Progress */}
                <div className="quota-card">
                  <div className="quota-header">
                    <span>Google Apps Script Pool Daily Quota</span>
                    <span className="mono">{totalRequests} / {maxRequests} runs ({quotaPercent.toFixed(1)}%)</span>
                  </div>
                  <div className="quota-progress">
                    <div className="quota-fill" style={{ width: `${quotaPercent}%` }} />
                  </div>
                  <div className="quota-legend">
                    <span>Low Usage</span>
                    <span>Quota Limit</span>
                  </div>
                </div>

                {/* Stat Cards */}
                <div className="info-cards-grid">
                  <div className="info-card">
                    <span className="card-icon">🖧</span>
                    <div className="card-content">
                      <h3>Active Relays</h3>
                      <p>{activeCount} nodes</p>
                    </div>
                  </div>

                  <div className="info-card">
                    <span className="card-icon">⚡</span>
                    <div className="card-content">
                      <h3>Error Rate</h3>
                      <p>{status?.gcloud_metrics.error_count_5xx || 0} fails</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {view === 'nodes' && (
          <div className="view-container">
            <header className="view-header">
              <h1>Google Apps Script Pools</h1>
              <p>Add URLs to the smart L7 weighted least-latency pool with automatic circuit breakers</p>
            </header>

            {/* Add Node Form */}
            <form onSubmit={handleAddNode} className="nodes-controls">
              <input
                type="text"
                className="add-node-input"
                placeholder="Paste Google Apps Script execute URL (https://script.google.com/.../exec)"
                value={newNodeUrl}
                onChange={e => setNewNodeUrl(e.target.value)}
                required
              />
              <button type="submit" className="add-node-btn">Add URL</button>
            </form>

            {/* Nodes List */}
            <div className="nodes-list">
              {nodes.length === 0 ? (
                <div className="quota-card" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
                  No GAS nodes in pool. Add your script URLs to begin tunneling!
                </div>
              ) : (
                nodes.map(node => (
                  <div key={node.id} className="node-row">
                    <div className="node-info-left">
                      <span className={`node-indicator ${node.status.toLowerCase()}`} />
                      <div className="node-url-wrap">
                        <div className="node-url">{node.url}</div>
                        <div className="node-stats">
                          <span className="stat-item">Avg Ping: <span>{node.average_latency_ms}ms</span></span>
                          <span className="stat-item">Fails: <span>{node.failed_requests}</span></span>
                          <span className="stat-item">Status: <span style={{ textTransform: 'capitalize' }}>{node.status}</span></span>
                        </div>
                      </div>
                    </div>

                    <div className="node-actions">
                      <button
                        className="action-btn"
                        onClick={() => handleToggleNode(node.id, node.status)}
                      >
                        {node.status === 'Active' ? 'Pause' : 'Activate'}
                      </button>
                      <button
                        className="action-btn"
                        disabled={testingNodeId === node.id}
                        onClick={() => handleTestNode(node.id)}
                      >
                        {testingNodeId === node.id ? <span className="spinner" /> : 'Ping Check'}
                      </button>
                      <button
                        className="action-btn delete"
                        onClick={() => handleDeleteNode(node.id)}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {view === 'settings' && (
          <div className="view-container">
            <header className="view-header">
              <h1>Application Settings</h1>
              <p>Configure local proxy ports, decryption keys, and Google Cloud credentials</p>
            </header>

            <form onSubmit={handleSaveSettings} className="settings-form">
              <div className="form-row">
                <div className="form-group">
                  <label>SOCKS5 Listen Address</label>
                  <input
                    type="text"
                    value={socksAddrInput}
                    onChange={e => setSocksAddrInput(e.target.value)}
                    placeholder=":1080"
                    required
                  />
                </div>

                <div className="form-group">
                  <label>Pre-Shared Key (PSK) - Hex String</label>
                  <input
                    type="password"
                    value={pskInput}
                    onChange={e => setPskInput(e.target.value)}
                    placeholder="64 hex chars = 32 bytes"
                    required
                  />
                </div>
              </div>

              <div style={{ margin: '10px 0', borderBottom: '1px solid var(--border-primary)' }} />

              <h2 style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Google Cloud API (Direct Quota Monitoring)
              </h2>

              <div className="form-group">
                <label>Google OAuth Client ID</label>
                <input
                  type="text"
                  value={clientIDInput}
                  onChange={e => setClientIDInput(e.target.value)}
                  placeholder="Optional Client ID"
                />
              </div>

              <div className="form-group">
                <label>Google OAuth Client Secret</label>
                <input
                  type="password"
                  value={clientSecretInput}
                  onChange={e => setClientSecretInput(e.target.value)}
                  placeholder="Optional Client Secret"
                />
              </div>

              <div className="form-group">
                <label>Google OAuth Refresh Token</label>
                <input
                  type="password"
                  value={refreshTokenInput}
                  onChange={e => setRefreshTokenInput(e.target.value)}
                  placeholder="Optional Refresh Token"
                />
              </div>

              <button type="submit" className="save-settings-btn">Save Settings & Keys</button>
            </form>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
