import { useState, useEffect, useCallback } from 'react'
import { getStats, getStatsWindows } from '../api'
import Sparkline from '../components/Sparkline'

const METRICS = [
  { key: 'rx_packets',      label: '收包数',     color: '#6366f1' },
  { key: 'parse_failed',    label: '解析失败',   color: '#ef4444' },
  { key: 'rule_candidates', label: '进入匹配',   color: '#f59e0b' },
  { key: 'matched_rules',   label: '规则命中',   color: '#10b981' },
  { key: 'ringbuf_dropped', label: '缓冲区丢弃', color: '#8b5cf6' },
]

const RULE_METRICS = [
  { key: 'total_rules',   label: '规则总数', color: '#6366f1' },
  { key: 'enabled_rules', label: '已启用',   color: '#10b981' },
]

const DEFAULT_WINDOWS = ['10min']

function computeDeltas(points, key) {
  if (!points || points.length < 1) return { deltas: [], timestamps: [] }
  if (points.length === 1) return { deltas: [points[0][key]], timestamps: [points[0].timestamp] }
  const deltas = []
  const timestamps = []
  for (let i = 1; i < points.length; i++) {
    const diff = points[i][key] - points[i - 1][key]
    deltas.push(diff)
    timestamps.push(points[i].timestamp)
  }
  return { deltas, timestamps }
}

function extractValues(points, key) {
  if (!points || points.length < 1) return { deltas: [], timestamps: [] }
  if (points.length === 1) return { deltas: [points[0][key]], timestamps: [points[0].timestamp] }
  const deltas = []
  const timestamps = []
  for (let i = 1; i < points.length; i++) {
    deltas.push(points[i][key])
    timestamps.push(points[i].timestamp)
  }
  return { deltas, timestamps }
}

function formatTimestamp(iso) {
  const d = new Date(iso)
  const h = d.getHours().toString().padStart(2, '0')
  const m = d.getMinutes().toString().padStart(2, '0')
  const s = d.getSeconds().toString().padStart(2, '0')
  return `${h}:${m}:${s}`
}

export default function StatsPage() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')
  const [window, setWindow] = useState('')
  const [windows, setWindows] = useState(DEFAULT_WINDOWS)

  useEffect(() => {
    getStatsWindows()
      .then(data => { if (Array.isArray(data) && data.length > 0) setWindows(data) })
      .catch(() => {})
  }, [])

  const load = useCallback((w) => {
    getStats(w)
      .then(setStats)
      .catch(err => setError(err.message))
  }, [])

  useEffect(() => { load(window) }, [load, window])

  if (error) {
    return (
      <>
        <div className="page-header">
          <h1>统计信息</h1>
          <p>数据面流量统计与增量趋势</p>
        </div>
        <div className="page-body">
          <div className="error-block">加载失败：{error}</div>
        </div>
      </>
    )
  }

  if (!stats) {
    return (
      <>
        <div className="page-header">
          <h1>统计信息</h1>
          <p>数据面流量统计与增量趋势</p>
        </div>
        <div className="page-body"><div className="loading">加载中...</div></div>
      </>
    )
  }

  const histories = stats.histories || []
  const series = histories.length > 0 ? histories[0] : null
  const points = series?.points || []
  const hasHistory = points.length >= 1

  const activeWindow = window || (series?.name || '')

  return (
    <>
      <div className="page-header">
        <h1>统计信息</h1>
        <p>数据面流量统计与增量趋势</p>
      </div>
      <div className="page-body">
        {/* Current values */}
        <div className="status-cards" style={{ marginBottom: 24 }}>
          {METRICS.map(m => (
            <div className="status-card" key={m.key}>
              <div className="status-card-label">{m.label}</div>
              <div className="status-card-value" style={{ fontSize: 20 }}>
                {formatValue(stats[m.key])}
              </div>
            </div>
          ))}
        </div>

        {/* Window selector */}
        <div className="window-selector">
          {windows.map(w => (
            <button
              key={w}
              className={`btn btn-sm ${activeWindow === w ? 'btn-primary' : ''}`}
              onClick={() => setWindow(w)}
            >
              {w}
            </button>
          ))}
        </div>

        {/* Charts from history */}
        {hasHistory ? (
          <>
            {METRICS.map(m => {
              const { deltas, timestamps } = computeDeltas(points, m.key)
              if (deltas.length < 1) return null
              return (
                <div className="section" key={m.key}>
                  <div className="section-title">{m.label}（增量/采样间隔）</div>
                  <div className="chart-container">
                    <Sparkline
                      data={deltas}
                      color={m.color}
                      labels={timestamps.map(formatTimestamp)}
                    />
                  </div>
                </div>
              )
            })}
            {RULE_METRICS.map(m => {
              const { deltas, timestamps } = extractValues(points, m.key)
              if (deltas.length < 1) return null
              return (
                <div className="section" key={m.key}>
                  <div className="section-title">{m.label}</div>
                  <div className="chart-container">
                    <Sparkline
                      data={deltas}
                      color={m.color}
                      labels={timestamps.map(formatTimestamp)}
                    />
                  </div>
                </div>
              )
            })}
          </>
        ) : (
          <div className="section">
            <div className="section-title">趋势图</div>
            <div style={{ color: 'var(--c-text-placeholder)', fontSize: 13, padding: '16px 0' }}>
              暂无历史数据
            </div>
          </div>
        )}
      </div>
    </>
  )
}

function formatValue(n) {
  return n.toLocaleString()
}
