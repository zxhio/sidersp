import { useCallback, useEffect, useState } from 'react'
import { listResponseResults } from '../api'

const PAGE_SIZE = 20

const ACTION_OPTIONS = [
  '',
  'icmp_echo_reply',
  'arp_reply',
  'tcp_syn_ack',
  'udp_echo_reply',
  'dns_refused',
  'dns_sinkhole',
]

const RESULT_OPTIONS = ['', 'sent', 'failed', 'skipped']
const BACKEND_OPTIONS = ['', 'afxdp', 'afpacket']

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
    txBackend: '',
  })
  const [draft, setDraft] = useState({
    ruleID: '',
    action: '',
    result: '',
    txBackend: '',
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
        tx_backend: nextQuery.txBackend,
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
      txBackend: draft.txBackend,
    })
  }

  function clearFilters() {
    const next = { ruleID: '', action: '', result: '', txBackend: '' }
    setDraft(next)
    setQuery({
      page: 1,
      pageSize: PAGE_SIZE,
      ruleID: '',
      action: '',
      result: '',
      txBackend: '',
    })
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <>
      <div className="page-header">
        <h1>响应结果</h1>
        <p>查看用户态响应执行结果的内存缓冲区，默认按最新结果优先展示</p>
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
                {ACTION_OPTIONS.filter(Boolean).map(item => (
                  <option key={item} value={item}>{item}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>结果</label>
              <select
                value={draft.result}
                onChange={e => setDraft(current => ({ ...current, result: e.target.value }))}
              >
                <option value="">全部</option>
                {RESULT_OPTIONS.filter(Boolean).map(item => (
                  <option key={item} value={item}>{item}</option>
                ))}
              </select>
            </div>
            <div className="form-group">
              <label>发送后端</label>
              <select
                value={draft.txBackend}
                onChange={e => setDraft(current => ({ ...current, txBackend: e.target.value }))}
              >
                <option value="">全部</option>
                {BACKEND_OPTIONS.filter(Boolean).map(item => (
                  <option key={item} value={item}>{item}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="overview-actions">
            <button type="submit" className="btn btn-primary">查询</button>
            <button type="button" className="btn" onClick={clearFilters}>清空</button>
          </div>
        </form>

        <div className="toolbar">
          <span className="toolbar-info">共 {total} 条结果</span>
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
                    <th>后端</th>
                    <th>队列</th>
                    <th>五元组</th>
                    <th>错误</th>
                  </tr>
                </thead>
                <tbody>
                  {items.length === 0 ? (
                    <tr className="empty-row">
                      <td colSpan={8}>暂无响应结果数据</td>
                    </tr>
                  ) : items.map(item => (
                    <tr key={`${item.timestamp_ns}-${item.rule_id}-${item.action}-${item.result}`}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{formatTimestamp(item.timestamp)}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{item.rule_id}</td>
                      <td><span className={`tag ${resultClass(item.result)}`}>{item.result}</span></td>
                      <td><span className="tag tag-success">{item.action}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{item.tx_backend}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{item.rx_queue}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{formatTuple(item)}</td>
                      <td style={{ maxWidth: 320, whiteSpace: 'normal', wordBreak: 'break-word' }}>{item.error || '-'}</td>
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
      </div>
    </>
  )
}

function formatTimestamp(iso) {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString('zh-CN', { hour12: false })
}

function formatTuple(item) {
  const protocol = item.ip_proto ? String(item.ip_proto) : '-'
  return `${protocol} ${item.sip || '-'}:${item.sport || 0} -> ${item.dip || '-'}:${item.dport || 0}`
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
