import { useState, useEffect } from 'react'
import { getStatus } from '../api'

export default function OverviewPage() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getStatus()
      .then(setStatus)
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

  if (!status) {
    return (
      <>
        <PageHeader title="概览" desc="系统运行状态总览" />
        <div className="page-body"><div className="loading">加载中...</div></div>
      </>
    )
  }

  const disabledCount = status.total_rules - status.enabled_rules

  return (
    <>
      <PageHeader title="概览" desc="系统运行状态总览" />
      <div className="page-body">
        {/* Key metrics */}
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
            <div className="status-card-label">规则总数</div>
            <div className="status-card-value">{status.total_rules}</div>
          </div>
          <div className="status-card">
            <div className="status-card-label">已启用</div>
            <div className="status-card-value">{status.enabled_rules}</div>
          </div>
          <div className="status-card">
            <div className="status-card-label">已禁用</div>
            <div className="status-card-value">{disabledCount}</div>
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
