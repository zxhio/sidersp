import { useState, useEffect } from 'react'
import { getStatus, getStats } from '../api'

export default function OverviewPage() {
  const [status, setStatus] = useState(null)
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([getStatus(), getStats()])
      .then(([statusData, statsData]) => {
        setStatus(statusData)
        setStats(statsData)
      })
      .catch(err => setError(err.message))
  }, [])

  if (error) {
    return (
      <>
        <PageHeader title="概览" desc="系统运行状态总览" />
        <div className="page-body">
          <div className="error-block">加载失败：{error}</div>
        </div>
      </>
    )
  }

  if (!status || !stats) {
    return (
      <>
        <PageHeader title="概览" desc="系统运行状态总览" />
        <div className="page-body"><div className="loading">加载中...</div></div>
      </>
    )
  }

  const enabledSummary = `${status.enabled_rules}/${status.total_rules}`

  return (
    <>
      <PageHeader title="概览" desc="系统运行状态总览" />
      <div className="page-body">
        <div className="status-cards" style={{ marginBottom: 24 }}>
          <div className="status-card">
            <div className="status-card-label">监听地址</div>
            <div className="status-card-value mono">{status.listen_addr || '-'}</div>
          </div>
          <div className="status-card">
            <div className="status-card-label">数据接口</div>
            <div className="status-card-value mono">{status.interface || '-'}</div>
          </div>
          <div className="status-card">
            <div className="status-card-label">发送网卡</div>
            <div className="status-card-value mono">{status.tx_interface || '-'}</div>
          </div>
        </div>

        <div className="section">
          <div className="section-title">规则状态</div>
          <div className="field-list">
            <div className="field-row">
              <div className="field-label">规则数</div>
              <div className="field-value">{status.total_rules}</div>
            </div>
            <div className="field-row">
              <div className="field-label">启用</div>
              <div className="field-value">{status.enabled_rules}</div>
            </div>
          </div>
        </div>

        <div className="section">
          <div className="section-title">统计状态</div>
          <div className="field-list">
            <div className="field-row">
              <div className="field-label">收包数</div>
              <div className="field-value">{formatValue(stats.rx_packets)}</div>
            </div>
            <div className="field-row">
              <div className="field-label">解析失败</div>
              <div className="field-value">{formatValue(stats.parse_failed)}</div>
            </div>
            <div className="field-row">
              <div className="field-label">匹配数量</div>
              <div className="field-value">{formatValue(stats.rule_candidates)}</div>
            </div>
            <div className="field-row">
              <div className="field-label">规则命中</div>
              <div className="field-value">{formatValue(stats.matched_rules)}</div>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

function PageHeader({ title, desc }) {
  return (
    <div className="page-header">
      <h1>{title}</h1>
      {desc && <p>{desc}</p>}
    </div>
  )
}

function formatValue(n) {
  return n.toLocaleString()
}
