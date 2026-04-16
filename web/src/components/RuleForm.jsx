import { useState } from 'react'

const EMPTY_RULE = {
  id: 0,
  name: '',
  enabled: true,
  priority: 100,
  match: {
    vlans: [],
    src_prefixes: [],
    dst_prefixes: [],
    src_ports: [],
    dst_ports: [],
    features: [],
  },
  response: { action: 'RST' },
}

function joinArr(arr) {
  return (arr || []).join(', ')
}

function splitArr(str) {
  return str.split(',').map(s => s.trim()).filter(Boolean)
}

function splitNumArr(str) {
  return str.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n))
}

export default function RuleForm({ rule, onSubmit, onCancel }) {
  const isNew = !rule
  const initial = rule || EMPTY_RULE

  const [form, setForm] = useState({
    id: initial.id,
    name: initial.name,
    enabled: initial.enabled,
    priority: initial.priority,
    vlans: joinArr(initial.match.vlans),
    src_prefixes: joinArr(initial.match.src_prefixes),
    dst_prefixes: joinArr(initial.match.dst_prefixes),
    src_ports: joinArr(initial.match.src_ports),
    dst_ports: joinArr(initial.match.dst_ports),
    features: joinArr(initial.match.features),
    action: initial.response.action,
  })
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  function set(key, value) {
    setForm(f => ({ ...f, [key]: value }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')

    const id = parseInt(form.id, 10)
    if (isNew && (isNaN(id) || id <= 0)) {
      setError('ID 必须为正整数')
      return
    }
    if (!form.name.trim()) {
      setError('规则名称不能为空')
      return
    }

    const payload = {
      id: isNew ? id : rule.id,
      name: form.name.trim(),
      enabled: form.enabled,
      priority: parseInt(form.priority, 10) || 0,
      match: {
        vlans: splitNumArr(form.vlans),
        src_prefixes: splitArr(form.src_prefixes),
        dst_prefixes: splitArr(form.dst_prefixes),
        src_ports: splitNumArr(form.src_ports),
        dst_ports: splitNumArr(form.dst_ports),
        features: splitArr(form.features),
      },
      response: { action: form.action },
    }

    setSubmitting(true)
    try {
      await onSubmit(payload)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{isNew ? '新建规则' : '编辑规则'}</h3>
          <button className="modal-close" onClick={onCancel}>&times;</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            {error && <div className="error-msg">{error}</div>}

            <div className="form-section-title">基本信息</div>
            <div className="form-row">
              <div className="form-group">
                <label>规则 ID <span className="required">*</span></label>
                <input
                  type="number"
                  value={form.id}
                  onChange={e => set('id', e.target.value)}
                  disabled={!isNew}
                  placeholder="正整数"
                />
              </div>
              <div className="form-group">
                <label>优先级</label>
                <input
                  type="number"
                  value={form.priority}
                  onChange={e => set('priority', e.target.value)}
                />
              </div>
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>规则名称 <span className="required">*</span></label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => set('name', e.target.value)}
                  placeholder="输入规则名称"
                />
              </div>
              <div className="form-group">
                <label style={{ marginTop: 22 }}>
                  <span className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={form.enabled}
                      onChange={e => set('enabled', e.target.checked)}
                    />
                    创建后立即启用
                  </span>
                </label>
              </div>
            </div>

            <div className="form-section-title">匹配条件</div>
            <div className="form-section-desc">多个值用英文逗号分隔，留空表示不限制</div>
            <div className="form-row">
              <div className="form-group">
                <label>VLAN</label>
                <input
                  type="text"
                  value={form.vlans}
                  onChange={e => set('vlans', e.target.value)}
                  placeholder="如 100, 200"
                />
              </div>
              <div className="form-group">
                <label>特征</label>
                <input
                  type="text"
                  value={form.features}
                  onChange={e => set('features', e.target.value)}
                  placeholder="如 tcp, udp"
                />
              </div>
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>源地址前缀</label>
                <input
                  type="text"
                  value={form.src_prefixes}
                  onChange={e => set('src_prefixes', e.target.value)}
                  placeholder="如 10.0.0.0/8"
                />
              </div>
              <div className="form-group">
                <label>目的地址前缀</label>
                <input
                  type="text"
                  value={form.dst_prefixes}
                  onChange={e => set('dst_prefixes', e.target.value)}
                  placeholder="如 192.168.0.0/16"
                />
              </div>
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>源端口</label>
                <input
                  type="text"
                  value={form.src_ports}
                  onChange={e => set('src_ports', e.target.value)}
                  placeholder="如 80, 443"
                />
              </div>
              <div className="form-group">
                <label>目的端口</label>
                <input
                  type="text"
                  value={form.dst_ports}
                  onChange={e => set('dst_ports', e.target.value)}
                  placeholder="如 80, 443"
                />
              </div>
            </div>

            <div className="form-section-title">响应动作</div>
            <div className="form-group">
              <label>动作类型</label>
              <select value={form.action} onChange={e => set('action', e.target.value)}>
                <option value="RST">RST (发送 TCP RST)</option>
              </select>
            </div>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn" onClick={onCancel}>取消</button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? '提交中...' : isNew ? '创建' : '保存'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
