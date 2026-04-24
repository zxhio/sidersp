import { useState, useEffect, useCallback } from 'react'
import { listRules, createRule, updateRule, deleteRule, enableRule, disableRule } from '../api'
import RuleForm from '../components/RuleForm'
import { useResizableColumns } from '../components/ResizableTable'

const PAGE_SIZE = 20

const DEFAULT_COL = {
  id: 40,
  name: 60,
  status: 50,
  priority: 50,
  action: 70,
  operations: 100,
}

function formatTCPFlags(flags) {
  if (!flags) return ''

  return Object.entries(flags)
    .filter(([, enabled]) => enabled)
    .map(([name]) => name.toUpperCase())
    .join(', ')
}

function formatProtocol(protocol) {
  return protocol ? protocol.toUpperCase() : ''
}

function MatchDetail({ match }) {
  const items = []
  if (match.protocol) items.push({ k: '协议', v: formatProtocol(match.protocol) })
  if (match.vlans?.length) items.push({ k: 'VLAN', v: match.vlans.join(', ') })
  if (match.src_prefixes?.length) items.push({ k: '源地址', v: match.src_prefixes.join(', ') })
  if (match.dst_prefixes?.length) items.push({ k: '目的地址', v: match.dst_prefixes.join(', ') })
  if (match.src_ports?.length) items.push({ k: '源端口', v: match.src_ports.join(', ') })
  if (match.dst_ports?.length) items.push({ k: '目的端口', v: match.dst_ports.join(', ') })
  if (formatTCPFlags(match.tcp_flags)) items.push({ k: 'TCP Flags', v: formatTCPFlags(match.tcp_flags) })
  if (match.icmp?.type) items.push({ k: 'ICMP 类型', v: match.icmp.type })
  if (match.arp?.operation) items.push({ k: 'ARP 操作', v: match.arp.operation })

  if (!items.length) return <span style={{ color: 'var(--c-text-placeholder)' }}>无匹配条件</span>

  return (
    <div className="match-detail">
      {items.map((item, i) => (
        <span key={i} className="match-item">
          <span className="match-key">{item.k}:</span>
          <span className="match-val">{item.v}</span>
        </span>
      ))}
    </div>
  )
}

function ConfirmDialog({ title, message, hint, onConfirm, onCancel }) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal" style={{ width: 400 }} onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{title}</h3>
          <button type="button" className="modal-close" onClick={onCancel}>&times;</button>
        </div>
        <div className="confirm-body">
          <p>{message}</p>
          {hint && <p className="confirm-hint">{hint}</p>}
        </div>
        <div className="confirm-footer">
          <button type="button" className="btn" onClick={onCancel}>取消</button>
          <button type="button" className="btn btn-primary" style={{ background: 'var(--c-danger)', borderColor: 'var(--c-danger)' }} onClick={onConfirm}>确认删除</button>
        </div>
      </div>
    </div>
  )
}

export default function RulesPage() {
  const [rules, setRules] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [formState, setFormState] = useState(null) // null | 'create' | rule object
  const [deleteTarget, setDeleteTarget] = useState(null) // null | rule object
  const { colStyle, onResizeStart } = useResizableColumns(DEFAULT_COL)

  const load = useCallback(async (p) => {
    setLoading(true)
    setError('')
    try {
      const res = await listRules(p, PAGE_SIZE)
      setRules(res.rules)
      setTotal(res.total)
      setPage(res.page)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(page) }, [load, page])

  const totalPages = Math.ceil(total / PAGE_SIZE)

  async function handleToggle(rule) {
    try {
      if (rule.enabled) {
        await disableRule(rule.id)
      } else {
        await enableRule(rule.id)
      }
      setRules(items => items.map(item => (
        item.id === rule.id ? { ...item, enabled: !item.enabled } : item
      )))
    } catch (err) {
      alert(err.message)
    }
  }

  async function handleConfirmDelete() {
    if (!deleteTarget) return
    try {
      await deleteRule(deleteTarget.id)
      setDeleteTarget(null)
      load(page)
    } catch (err) {
      alert(err.message)
    }
  }

  async function handleFormSubmit(payload) {
    if (formState === 'create') {
      await createRule(payload)
    } else {
      await updateRule(formState.id, payload)
    }
    setFormState(null)
    load(page)
  }

  return (
    <>
      <div className="page-header">
        <h1>规则管理</h1>
        <p>管理流量过滤规则的增删改查与启停</p>
      </div>
      <div className="page-body">
        {error && <div className="error-block" style={{ marginBottom: 16 }}>加载失败：{error}</div>}

        {/* Toolbar: action bar */}
        <div className="toolbar">
          <span className="toolbar-info">
            共 {total} 条规则
          </span>
          <button type="button" className="btn btn-primary" onClick={() => setFormState('create')}>
            新建规则
          </button>
        </div>

        {/* Table */}
        <div className="table-wrap">
          {loading ? (
            <div className="loading">加载中...</div>
          ) : (
            <>
              <table>
                <thead>
                  <tr>
                    <th style={colStyle('id')}>
                      ID
                      <span className="resize-handle" onMouseDown={e => onResizeStart('id', e)} />
                    </th>
                    <th style={colStyle('name')}>
                      名称
                      <span className="resize-handle" onMouseDown={e => onResizeStart('name', e)} />
                    </th>
                    <th style={colStyle('status')}>
                      状态
                      <span className="resize-handle" onMouseDown={e => onResizeStart('status', e)} />
                    </th>
                    <th style={colStyle('priority')}>
                      优先级
                      <span className="resize-handle" onMouseDown={e => onResizeStart('priority', e)} />
                    </th>
                    <th>匹配条件</th>
                    <th style={colStyle('action')}>
                      响应动作
                      <span className="resize-handle" onMouseDown={e => onResizeStart('action', e)} />
                    </th>
                    <th style={{ ...colStyle('operations'), textAlign: 'center' }}>
                      操作
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rules.length === 0 ? (
                    <tr className="empty-row">
                      <td colSpan={7}>暂无规则数据</td>
                    </tr>
                  ) : (
                    rules.map(rule => (
                      <tr key={rule.id}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{rule.id}</td>
                        <td>{rule.name}</td>
                        <td>
                          <button
                            type="button"
                            className={`toggle ${rule.enabled ? 'on' : ''}`}
                            onClick={() => handleToggle(rule)}
                            title={rule.enabled ? '点击禁用' : '点击启用'}
                          />
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{rule.priority}</td>
                        <td><MatchDetail match={rule.match} /></td>
                        <td>
                          <span className="tag tag-success">{rule.response.action}</span>
                        </td>
                        <td>
                          <div className="actions-cell">
                            <button type="button" className="btn btn-link btn-sm" onClick={() => setFormState(rule)}>
                              编辑
                            </button>
                            <button type="button" className="btn btn-danger-text btn-sm" onClick={() => setDeleteTarget(rule)}>
                              删除
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
              {totalPages > 1 && (
                <div className="pagination">
                  <span>第 {page} / {totalPages} 页</span>
                  <div className="pagination-buttons">
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={page <= 1}
                      onClick={() => setPage(p => p - 1)}
                    >
                      上一页
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={page >= totalPages}
                      onClick={() => setPage(p => p + 1)}
                    >
                      下一页
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Rule form modal */}
        {formState !== null && (
          <RuleForm
            rule={formState === 'create' ? null : formState}
            onSubmit={handleFormSubmit}
            onCancel={() => setFormState(null)}
          />
        )}

        {/* Delete confirm */}
        {deleteTarget && (
          <ConfirmDialog
            title="删除确认"
            message={`确定要删除规则「${deleteTarget.name}」（ID: ${deleteTarget.id}）吗？`}
            hint="删除后不可恢复"
            onConfirm={handleConfirmDelete}
            onCancel={() => setDeleteTarget(null)}
          />
        )}
      </div>
    </>
  )
}
