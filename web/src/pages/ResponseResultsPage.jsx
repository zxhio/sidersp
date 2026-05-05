import { useCallback, useEffect, useState } from 'react'
import { listResponseResults } from '../api'
import {
  RESPONSE_ACTION_OPTIONS,
  RESPONSE_RESULT_OPTIONS,
  formatActionLabel,
  formatResponseResultLabel,
  formatResponseTXBackendLabel,
} from '../labels'

const PAGE_SIZE = 20

export default function ResponseResultsPage() {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState({
    page: 1,
    pageSize: PAGE_SIZE,
    ruleID: '',
    action: '',
    result: '',
  })
  const [draft, setDraft] = useState({
    ruleID: '',
    action: '',
    result: '',
  })
  const [visibleColumns, setVisibleColumns] = useState({
    backend: false,
    queue: false,
  })

  const load = useCallback(async (nextQuery) => {
    setLoading(true)
    setError('')
    try {
      const data = await listResponseResults({
        page: nextQuery.page,
        page_size: nextQuery.pageSize,
        rule_id: nextQuery.ruleID,
        action: nextQuery.action,
        result: nextQuery.result,
      })
      setItems(data.items)
      setTotal(data.total)
      setPage(data.page)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(query)
  }, [load, query])

  function submitFilters(e) {
    e.preventDefault()
    setQuery({
      page: 1,
      pageSize: PAGE_SIZE,
      ruleID: draft.ruleID.trim(),
      action: draft.action,
      result: draft.result,
    })
  }

  function clearFilters() {
    const next = { ruleID: '', action: '', result: '' }
    setDraft(next)
    setQuery({
      page: 1,
      pageSize: PAGE_SIZE,
      ruleID: '',
      action: '',
      result: '',
    })
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const columnCount = 6 + (visibleColumns.backend ? 1 : 0) + (visibleColumns.queue ? 1 : 0)

  return (
    <>
      <div className="page-header">
        <h1>响应结果</h1>
        <p>查看用户态响应执行结果的内存缓冲区，默认按最新结果优先展示</p>
      </div>
      <div className="page-body">
        {error && <div className="error-block" style={{ marginBottom: 16 }}>加载失败：{error}</div>}

        <form className="table-wrap" style={{ padding: '10px 16px', marginBottom: 12 }} onSubmit={submitFilters}>
          <div className="form-row" style={{ gridTemplateColumns: '1fr 1fr 1fr auto' }}>
            <div className="form-group">
              <label>规则 ID</label>
              <input
                type="number"
                min="1"
                value={draft.ruleID}
                onChange={e => setDraft(current => ({ ...current, ruleID: e.target.value }))}
                placeholder="如 2001"
              />
            </div>
            <div className="form-group">
              <label>动作</label>
              <select
                value={draft.action}
                onChange={e => setDraft(current => ({ ...current, action: e.target.value }))}
              >
                <option value="">全部</option>
                {RESPONSE_ACTION_OPTIONS.map(item => (
                  <option key={item.value} value={item.value}>{item.label}</option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label>响应结果</label>
              <select
                value={draft.result}
                onChange={e => setDraft(current => ({ ...current, result: e.target.value }))}
              >
                <option value="">全部</option>
                {RESPONSE_RESULT_OPTIONS.map(item => (
                  <option key={item.value} value={item.value}>{item.label}</option>
                ))}
              </select>
            </div>
            <div className="form-group" style={{ display: 'flex', alignItems: 'flex-end', gap: 8 }}>
              <button type="submit" className="btn btn-primary">查询</button>
              <button type="button" className="btn" onClick={clearFilters}>清空</button>
            </div>
          </div>
        </form>

        <div className="toolbar">
          <div className="column-toggle-group">
            <label className="column-toggle">
              <input
                type="checkbox"
                checked={visibleColumns.backend}
                onChange={e => setVisibleColumns(current => ({ ...current, backend: e.target.checked }))}
              />
              显示发送路径
            </label>
            <label className="column-toggle">
              <input
                type="checkbox"
                checked={visibleColumns.queue}
                onChange={e => setVisibleColumns(current => ({ ...current, queue: e.target.checked }))}
              />
              显示队列
            </label>
          </div>
        </div>

        <div className="table-wrap">
          {loading ? (
            <div className="loading">加载中...</div>
          ) : (
            <>
              <table>
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>规则</th>
                    <th>结果</th>
                    <th>动作</th>
                    {visibleColumns.backend && <th>发送路径</th>}
                    {visibleColumns.queue && <th>队列</th>}
                    <th>五元组</th>
                    <th>错误</th>
                  </tr>
                </thead>
                <tbody>
                  {items.length === 0 ? (
                    <tr className="empty-row">
                      <td colSpan={columnCount}>暂无响应结果数据</td>
                    </tr>
                  ) : items.map(item => (
                    <tr key={`${item.timestamp_ns}-${item.rule_id}-${item.action}-${item.result}`}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{formatTimestamp(item.timestamp)}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{item.rule_id}</td>
                      <td><span className={`tag ${resultClass(item.result)}`} title={item.result}>{formatResponseResultLabel(item.result)}</span></td>
                      <td><span className="tag tag-success" title={item.action}>{formatActionLabel(item.action)}</span></td>
                      {visibleColumns.backend && <td><span className="tag tag-disabled" title={item.tx_backend}>{formatResponseTXBackendLabel(item.tx_backend)}</span></td>}
                      {visibleColumns.queue && <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{item.rx_queue}</td>}
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{formatTuple(item)}</td>
                      <td style={{ maxWidth: 320, whiteSpace: 'normal', wordBreak: 'break-word' }}>{item.error || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="pagination">
                <span>共 <strong>{total}</strong> 条 · 第 <strong>{page}</strong> / <strong>{totalPages}</strong> 页</span>
                <div className="pagination-buttons">
                  <button
                    type="button"
                    className="btn"
                    disabled={page <= 1}
                    onClick={() => setQuery(current => ({ ...current, page: current.page - 1 }))}
                  >
                    上一页
                  </button>
                  <button
                    type="button"
                    className="btn"
                    disabled={page >= totalPages}
                    onClick={() => setQuery(current => ({ ...current, page: current.page + 1 }))}
                  >
                    下一页
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  )
}

function formatTimestamp(iso) {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString('zh-CN', { hour12: false })
}

function formatTuple(item) {
  return `${item.sip || '-'}:${item.sport || 0} -> ${item.dip || '-'}:${item.dport || 0}`
}

function resultClass(result) {
  switch (result) {
    case 'failed':
      return 'tag-danger'
    case 'sent':
      return 'tag-success'
    default:
      return 'tag-disabled'
  }
}
