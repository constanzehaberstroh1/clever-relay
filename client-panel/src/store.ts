import { create } from 'zustand'

// ── Types ────────────────────────────────────────────────────────────────────

export interface LogEntry {
  timestamp: string
  level: string
  component: string
  message: string
  details?: string
  session_id?: string
  trace_id?: string
}

export interface NodeInfo {
  url: string
  state: string
  avg_latency_ms: number
  successes: number
  failures: number
  cooldown_at?: string
  enabled: boolean
}

export interface EngineStatus {
  status: string
  version: string
  build_time: string
  uptime_seconds: number
  uptime_human: string
  socks5_addr: string
  socks5_active: boolean
  active_sessions: number
  gas_nodes: number
  goroutines: number
  memory: {
    alloc_mb: number
    sys_mb: number
    gc_cycles: number
    heap_objects: number
  }
  logger: {
    total: number
    dropped: number
    buffered: number
  }
}

export interface PanelConfig {
  chunk_size: number
  flush_ms: number
  max_retries: number
  timeout_seconds: number
  parallel_pulls: number
  socks_addr: string
}

// ── API Helper ───────────────────────────────────────────────────────────────

const API_BASE = '/api'

async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) throw new Error(`API ${path}: ${res.status}`)
  return res.json()
}

// ── Store ────────────────────────────────────────────────────────────────────

interface StoreState {
  // Status
  status: EngineStatus | null
  statusLoading: boolean
  fetchStatus: () => Promise<void>

  // Nodes
  nodes: NodeInfo[]
  nodesLoading: boolean
  fetchNodes: () => Promise<void>
  addNode: (url: string) => Promise<void>
  removeNode: (url: string) => Promise<void>
  toggleNode: (url: string, state: string) => Promise<void>

  // Config
  config: PanelConfig | null
  configLoading: boolean
  fetchConfig: () => Promise<void>
  updateConfig: (cfg: Partial<PanelConfig>) => Promise<void>

  // Logs (bounded array, max 1000)
  logs: LogEntry[]
  errorCount: number
  wsConnected: boolean
  connectWS: () => void
  clearLogs: () => void
}

const MAX_LOGS = 1000

export const useStore = create<StoreState>((set, get) => ({
  // ── Status ─────────────────────────────────────────────────────────────────
  status: null,
  statusLoading: false,
  fetchStatus: async () => {
    set({ statusLoading: true })
    try {
      const data = await apiFetch<EngineStatus>('/status')
      set({ status: data })
    } catch (e) {
      console.error('fetchStatus error:', e)
    } finally {
      set({ statusLoading: false })
    }
  },

  // ── Nodes ──────────────────────────────────────────────────────────────────
  nodes: [],
  nodesLoading: false,
  fetchNodes: async () => {
    set({ nodesLoading: true })
    try {
      const data = await apiFetch<{ nodes: NodeInfo[] }>('/nodes')
      set({ nodes: data.nodes || [] })
    } catch (e) {
      console.error('fetchNodes error:', e)
    } finally {
      set({ nodesLoading: false })
    }
  },
  addNode: async (url: string) => {
    await apiFetch('/nodes/add', {
      method: 'POST',
      body: JSON.stringify({ url }),
    })
    get().fetchNodes()
  },
  removeNode: async (url: string) => {
    await apiFetch('/nodes/remove', {
      method: 'POST',
      body: JSON.stringify({ url }),
    })
    get().fetchNodes()
  },
  toggleNode: async (url: string, state: string) => {
    await apiFetch('/nodes/toggle', {
      method: 'POST',
      body: JSON.stringify({ url, state }),
    })
    get().fetchNodes()
  },

  // ── Config ─────────────────────────────────────────────────────────────────
  config: null,
  configLoading: false,
  fetchConfig: async () => {
    set({ configLoading: true })
    try {
      const data = await apiFetch<PanelConfig>('/config')
      set({ config: data })
    } catch (e) {
      console.error('fetchConfig error:', e)
    } finally {
      set({ configLoading: false })
    }
  },
  updateConfig: async (cfg: Partial<PanelConfig>) => {
    await apiFetch('/config', {
      method: 'POST',
      body: JSON.stringify(cfg),
    })
    get().fetchConfig()
  },

  // ── Logs ───────────────────────────────────────────────────────────────────
  logs: [],
  errorCount: 0,
  wsConnected: false,
  connectWS: () => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${proto}//${window.location.host}/ws/logs`
    let ws: WebSocket

    function connect() {
      ws = new WebSocket(wsUrl)
      ws.onopen = () => set({ wsConnected: true })
      ws.onclose = () => {
        set({ wsConnected: false })
        // Auto-reconnect after 2s
        setTimeout(connect, 2000)
      }
      ws.onerror = () => ws.close()
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'log' && msg.data) {
            const entry: LogEntry = msg.data
            set((state) => {
              const logs = [...state.logs, entry]
              if (logs.length > MAX_LOGS) logs.splice(0, logs.length - MAX_LOGS)
              const errorCount = entry.level === 'ERROR' || entry.level === 'WARN'
                ? state.errorCount + 1
                : state.errorCount
              return { logs, errorCount }
            })
          }
        } catch {
          // ignore malformed messages
        }
      }
    }

    connect()
  },
  clearLogs: () => set({ logs: [], errorCount: 0 }),
}))
