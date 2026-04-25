import { useState, useEffect, useCallback } from 'react'
import { getStats, getStatsWindows } from '../api'
import Sparkline from '../components/Sparkline'

const DEFAULT_WINDOWS = ['10min']

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
  xsk_tx: '#64748b',
  xsk_failed: '#be123c',
  xsk_meta_failed: '#991b1b',
  xsk_redirect_failed: '#c2410c',
  redirect_tx: '#14b8a6',
  redirect_failed: '#ea580c',
  fib_lookup_failed: '#9333ea',
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

function stageHeadline(overview, stages) {
  if (!overview?.primary_issue_stage) return '无明显异常'
  const stage = stages.find(item => item.key === overview.primary_issue_stage)
  return stage ? stage.title : overview.primary_issue_stage
}

export default function StatsPage() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')
  const [window, setWindow] = useState('')
  const [windows, setWindows] = useState(DEFAULT_WINDOWS)

  useEffect(() => {
    getStatsWindows()
      .then(data => {
        if (Array.isArray(data) && data.length > 0) setWindows(data)
      })
      .catch(() => {})
  }, [])

  const load = useCallback((w) => {
    setError('')
    getStats(w)
      .then(setStats)
      .catch(err => setError(err.message))
  }, [])

  useEffect(() => {
    load(window)
  }, [load, window])

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
  const activeWindow = window || historySeries?.name || ''

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
          <div className="status-card">
            <div className="status-card-label">当前重点排查</div>
            <div className="status-card-value" style={{ fontSize: 20 }}>
              {stageHeadline(overview, stages)}
            </div>
          </div>
        </div>

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
                        <div className="section-title">{metric.label}（增量/采样间隔）</div>
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
