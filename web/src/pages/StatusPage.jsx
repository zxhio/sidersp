import { useState, useEffect, useCallback } from 'react'
import { getStats } from '../api'
import Sparkline from '../components/Sparkline'

const DEFAULT_RANGES = [
  { label: '10m', seconds: 600 },
  { label: '1d', seconds: 86400 },
  { label: '30d', seconds: 2592000 },
]

const ROLE_COLORS = {
  traffic: '#2563eb',
  success: '#16a34a',
  failure: '#dc2626',
}

const METRIC_COLORS = {
  parse_failed: '#ef4444',
  ringbuf_dropped: '#8b5cf6',
  xdp_tx: '#0ea5e9',
  tx_failed: '#dc2626',
  xsk_redirected: '#64748b',
  xsk_redirect_failed: '#be123c',
  xsk_meta_failed: '#991b1b',
  xsk_map_redirect_failed: '#c2410c',
  redirect_tx: '#14b8a6',
  redirect_failed: '#ea580c',
  fib_lookup_failed: '#9333ea',
  response_sent: '#16a34a',
  response_failed: '#b91c1c',
  afxdp_tx: '#0284c7',
  afxdp_tx_failed: '#c2410c',
  afpacket_tx: '#0f766e',
  afpacket_tx_failed: '#7f1d1d',
}

const ROLE_LABELS = {
  traffic: '流量',
  success: '成功',
  failure: '失败',
}

function computeMetricDeltas(points) {
  if (!points || points.length < 1) return { deltas: [], timestamps: [] }
  if (points.length === 1) return { deltas: [points[0].value], timestamps: [points[0].timestamp] }
  const deltas = []
  const timestamps = []
  for (let i = 1; i < points.length; i++) {
    deltas.push(points[i].value - points[i - 1].value)
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

function formatValue(n) {
  return typeof n === 'number' ? n.toLocaleString() : '-'
}

function formatCompactUnit(value) {
  const rounded = Math.round(value * 100) / 100
  return Number.isInteger(rounded) ? `${rounded}` : `${rounded}`
}

function formatDurationFromSeconds(seconds) {
  if (!seconds || seconds <= 0) return '采样间隔'
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds >= 3600) return `${formatCompactUnit(seconds / 3600)}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

function metricColor(metric) {
  return METRIC_COLORS[metric.key] || ROLE_COLORS[metric.role] || '#64748b'
}

function roleClass(role) {
  switch (role) {
    case 'failure':
      return 'tag-danger'
    case 'success':
      return 'tag-success'
    default:
      return 'tag-disabled'
  }
}

function findStageHistory(stageHistories, stageKey) {
  return stageHistories.find(stage => stage.key === stageKey) || null
}

function findMetricHistory(stageHistory, metricKey) {
  if (!stageHistory || !Array.isArray(stageHistory.metrics)) return null
  return stageHistory.metrics.find(metric => metric.key === metricKey) || null
}

export default function StatsPage() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')
  const [rangeSeconds, setRangeSeconds] = useState(DEFAULT_RANGES[0].seconds)

  const load = useCallback((nextRangeSeconds) => {
    setError('')
    getStats(nextRangeSeconds)
      .then(setStats)
      .catch(err => setError(err.message))
  }, [])

  useEffect(() => {
    load(rangeSeconds)
  }, [load, rangeSeconds])

  if (error) {
    return (
      <>
        <div className="page-header">
          <h1>统计信息</h1>
          <p>按排查阶段查看数据面诊断状态与趋势</p>
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
          <p>按排查阶段查看数据面诊断状态与趋势</p>
        </div>
        <div className="page-body"><div className="loading">加载中...</div></div>
      </>
    )
  }

  const overview = stats.overview || {}
  const stages = Array.isArray(stats.stages) ? stats.stages : []
  const historySeries = Array.isArray(stats.stage_histories) && stats.stage_histories.length > 0 ? stats.stage_histories[0] : null
  const historyStages = historySeries?.stages || []
  const activeRangeSeconds = rangeSeconds || stats.range_seconds
  const displayStepLabel = formatDurationFromSeconds(stats.display_step_seconds)

  return (
    <>
      <div className="page-header">
        <h1>统计信息</h1>
        <p>按排查阶段查看数据面诊断状态与趋势</p>
      </div>
      <div className="page-body">
        <div className="status-cards diagnostic-overview" style={{ marginBottom: 24 }}>
          <div className="status-card">
            <div className="status-card-label">总收包</div>
            <div className="status-card-value" style={{ fontSize: 20 }}>
              {formatValue(overview.rx_packets ?? stats.rx_packets)}
            </div>
          </div>
          <div className="status-card">
            <div className="status-card-label">规则启用</div>
            <div className="status-card-value" style={{ fontSize: 20 }}>
              {`${formatValue(overview.enabled_rules ?? stats.enabled_rules)}/${formatValue(overview.total_rules ?? stats.total_rules)}`}
            </div>
          </div>
          <div className="status-card">
            <div className="status-card-label">规则命中</div>
            <div className="status-card-value" style={{ fontSize: 20 }}>
              {formatValue(overview.matched_rules ?? stats.matched_rules)}
            </div>
          </div>
        </div>

        <div className="window-selector">
          {DEFAULT_RANGES.map(item => (
            <button
              key={item.seconds}
              className={`btn btn-sm ${activeRangeSeconds === item.seconds ? 'btn-primary' : ''}`}
              onClick={() => setRangeSeconds(item.seconds)}
            >
              {item.label}
            </button>
          ))}
        </div>

        <div className="diagnostic-stage-list">
          {stages.map(stage => {
            const stageHistory = findStageHistory(historyStages, stage.key)
            return (
              <section className="diagnostic-stage" key={stage.key}>
                <div className="diagnostic-stage-head">
                  <div>
                    <h2 className="diagnostic-stage-title">{stage.title}</h2>
                    <p className="diagnostic-stage-summary">{stage.summary}</p>
                  </div>
                  <span className="tag tag-disabled">{stage.key}</span>
                </div>

                <div className="diagnostic-metrics">
                  {stage.metrics.map(metric => (
                    <div className="diagnostic-metric-card" key={metric.key}>
                      <div className="diagnostic-metric-head">
                        <div className="diagnostic-metric-label">{metric.label}</div>
                        <span className={`tag ${roleClass(metric.role)}`}>
                          {ROLE_LABELS[metric.role] || metric.role}
                        </span>
                      </div>
                      <div className="diagnostic-metric-value">{formatValue(metric.value)}</div>
                      <div className="diagnostic-metric-desc">{metric.description}</div>
                    </div>
                  ))}
                </div>

                <div className="diagnostic-history-grid">
                  {stage.metrics.map(metric => {
                    const history = findMetricHistory(stageHistory, metric.key)
                    const { deltas, timestamps } = computeMetricDeltas(history?.points || [])
                    if (deltas.length < 1) return null
                    return (
                      <div className="section" key={`${stage.key}-${metric.key}`}>
                        <div className="section-title">{metric.label}（增量/{displayStepLabel}）</div>
                        <div className="chart-container">
                          <Sparkline
                            data={deltas}
                            color={metricColor(metric)}
                            labels={timestamps.map(formatTimestamp)}
                          />
                        </div>
                      </div>
                    )
                  })}
                  {!stageHistory && (
                    <div className="diagnostic-empty">暂无该阶段历史数据</div>
                  )}
                </div>
              </section>
            )
          })}
        </div>
      </div>
    </>
  )
}
