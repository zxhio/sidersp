import { useCallback, useEffect, useState } from 'react'
import { listEvents } from '../api'
import {
  EVENT_ACTION_OPTIONS,
  EVENT_OUTCOME_HINTS,
  EVENT_OUTCOME_OPTIONS,
  formatActionLabel,
  formatEventOutcomeLabel,
  formatPacketConditionLabels,
} from '../labels'

const PAGE_SIZE = 20

export default function EventsPage() {
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
    verdict: '',
  })
  const [draft, setDraft] = useState({
    ruleID: '',
    action: '',
    verdict: '',
  })
  const [visibleColumns, setVisibleColumns] = useState({
    conditions: false,
  })
  const [helpTooltip, setHelpTooltip] = useState(null)

  const load = useCallback(async (nextQuery) => {
    setLoading(true)
    setError('')
    try {
      const data = await listEvents({
        page: nextQuery.page,
        page_size: nextQuery.pageSize,
        rule_id: nextQuery.ruleID,
        action: nextQuery.action,
        verdict: nextQuery.verdict,
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
      verdict: draft.verdict,
    })
  }

  function clearFilters() {
    const next = { ruleID: '', action: '', verdict: '' }
    setDraft(next)
    setQuery({
      page: 1,
      pageSize: PAGE_SIZE,
      ruleID: '',
      action: '',
      verdict: '',
    })
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const columnCount = visibleColumns.conditions ? 6 : 5
  const eventOutcomeHint = EVENT_OUTCOME_OPTIONS
    .map(item => `${item.label}：${EVENT_OUTCOME_HINTS[item.value]}`)
    .join('\n')

  function showHelpTooltip(event) {
    const rect = event.currentTarget.getBoundingClientRect()
    setHelpTooltip({
      text: eventOutcomeHint,
      left: rect.left + rect.width / 2,
      top: rect.bottom + 8,
    })
  }

  return (
    <>
      <div className="page-header">
        <h1>观测事件</h1>
        <p>查看 BPF 观测事件的内存缓冲区，默认按最新事件优先展示</p>
      </div>
      <div className="page-body">
        {error && <div className="error-block" style={{ marginBottom: 16 }}>加载失败：{error}</div>}

        <form className="table-wrap" style={{ padding: 16, marginBottom: 16 }} onSubmit={submitFilters}>
          <div className="form-row">
            <div className="form-group">
              <label>规则 ID</label>
              <input
                type="number"
                min="1"
                value={draft.ruleID}
                onChange={e => setDraft(current => ({ ...current, ruleID: e.target.value }))}
                placeholder="如 1001"
              />
            </div>
            <div className="form-group">
              <label>动作</label>
              <select
                value={draft.action}
                onChange={e => setDraft(current => ({ ...current, action: e.target.value }))}
              >
                <option value="">全部</option>
                {EVENT_ACTION_OPTIONS.map(item => (
                  <option key={item.value} value={item.value}>{item.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>观测结果</label>
              <select
                value={draft.verdict}
                onChange={e => setDraft(current => ({ ...current, verdict: e.target.value }))}
              >
                <option value="">全部</option>
                {EVENT_OUTCOME_OPTIONS.map(item => (
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
          <span className="toolbar-info">共 {total} 条事件</span>
          <label className="column-toggle">
            <input
              type="checkbox"
              checked={visibleColumns.conditions}
              onChange={e => setVisibleColumns(current => ({ ...current, conditions: e.target.checked }))}
            />
            显示条件
          </label>
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
                    <th>
                      <span className="th-with-help">
                        观测结果
                        <span
                          className="help-icon"
                          tabIndex={0}
                          onFocus={showHelpTooltip}
                          onBlur={() => setHelpTooltip(null)}
                          onMouseEnter={showHelpTooltip}
                          onMouseLeave={() => setHelpTooltip(null)}
                        >
                          ?
                        </span>
                      </span>
                    </th>
                    <th>动作</th>
                    <th>五元组</th>
                    {visibleColumns.conditions && <th>条件</th>}
                  </tr>
                </thead>
                <tbody>
                  {items.length === 0 ? (
                    <tr className="empty-row">
                      <td colSpan={columnCount}>暂无事件数据</td>
                    </tr>
                  ) : items.map(item => (
                    <tr key={`${item.timestamp_ns}-${item.rule_id}-${item.action}-${item.verdict}`}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{formatTimestamp(item.timestamp)}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{item.rule_id}</td>
                      <td><span className="tag tag-disabled" title={item.verdict}>{formatEventOutcomeLabel(item.verdict)}</span></td>
                      <td><span className="tag tag-success" title={item.action}>{formatActionLabel(item.action)}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{formatTuple(item)}</td>
                      {visibleColumns.conditions && (
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                          {formatPacketConditionLabels(item.pkt_cond_names)}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="pagination">
                <span>第 {page} / {totalPages} 页</span>
                <div className="pagination-buttons">
                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={page <= 1}
                    onClick={() => setQuery(current => ({ ...current, page: current.page - 1 }))}
                  >
                    上一页
                  </button>
                  <button
                    type="button"
                    className="btn btn-sm"
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
        {helpTooltip && (
          <div
            className="floating-help"
            style={{ left: helpTooltip.left, top: helpTooltip.top }}
          >
            {helpTooltip.text}
          </div>
        )}
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
