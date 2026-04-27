import { useState } from 'react'

const ACTION_GROUPS = [
  {
    label: '通用',
    options: [
      { value: 'alert', label: 'Alert' },
      { value: 'none', label: 'None' },
    ],
  },
  {
    label: 'TCP',
    options: [
      { value: 'tcp_reset', label: 'TCP Reset' },
      { value: 'tcp_syn_ack', label: 'TCP SYN-ACK' },
    ],
  },
  {
    label: 'UDP',
    options: [
      { value: 'icmp_port_unreachable', label: 'ICMP Port Unreachable' },
      { value: 'icmp_host_unreachable', label: 'ICMP Host Unreachable' },
      { value: 'icmp_admin_prohibited', label: 'ICMP Admin Prohibited' },
      { value: 'udp_echo_reply', label: 'UDP Echo Reply' },
      { value: 'dns_refused', label: 'DNS Refused' },
      { value: 'dns_sinkhole', label: 'DNS Sinkhole' },
    ],
  },
  {
    label: 'ICMP',
    options: [
      { value: 'icmp_echo_reply', label: 'ICMP Echo Reply' },
    ],
  },
  {
    label: 'ARP',
    options: [
      { value: 'arp_reply', label: 'ARP Reply' },
    ],
  },
]

const ACTION_OPTIONS = ACTION_GROUPS.flatMap(group => group.options)

const PROTOCOL_OPTIONS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'icmp', label: 'ICMP' },
  { value: 'arp', label: 'ARP' },
]
const ICMP_TYPE_OPTIONS = [
  { value: '', label: '不限' },
  { value: 'echo_request', label: 'Echo Request' },
  { value: 'echo_reply', label: 'Echo Reply' },
]
const ARP_OPERATION_OPTIONS = [
  { value: '', label: '不限' },
  { value: 'request', label: 'Request' },
  { value: 'reply', label: 'Reply' },
]
const TCP_FLAG_FIELDS = [
  { key: 'syn', label: 'SYN' },
  { key: 'ack', label: 'ACK' },
  { key: 'rst', label: 'RST' },
  { key: 'fin', label: 'FIN' },
  { key: 'psh', label: 'PSH' },
]
const TCP_RESET_FLAG_FIELDS = TCP_FLAG_FIELDS.filter(field => field.key !== 'rst')
const UDP_ONLY_ACTIONS = new Set([
  'icmp_port_unreachable',
  'icmp_host_unreachable',
  'icmp_admin_prohibited',
  'udp_echo_reply',
  'dns_refused',
  'dns_sinkhole',
])
const DNS_TTL_DEFAULT = 60
const DNS_TTL_MAX = 2147483647

const EMPTY_RULE = {
  name: '',
  enabled: true,
  priority: 100,
  match: {
    protocol: 'tcp',
    vlans: [],
    src_prefixes: [],
    dst_prefixes: [],
    src_ports: [],
    dst_ports: [],
    tcp_flags: {},
    icmp: null,
    arp: null,
  },
  response: { action: 'tcp_reset', params: {} },
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

function isKnownProtocol(protocol) {
  return PROTOCOL_OPTIONS.some(option => option.value === protocol)
}

function normalizePrefixValue(value) {
  if (!value || value.includes('/')) return value
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return `${value}/32`
  return value
}

function normalizePrefixesInput(str) {
  return splitArr(str).map(normalizePrefixValue)
}

function normalizeResponseParams(action, params) {
  if (action !== 'dns_sinkhole') {
    return {}
  }

  return {
    address: typeof params?.address === 'string' ? params.address : '',
    ttl: params?.ttl !== undefined && params?.ttl !== null ? String(params.ttl) : String(DNS_TTL_DEFAULT),
  }
}

function normalizeRule(rule) {
  if (!rule) return EMPTY_RULE

  const action = getActionOption(rule.response?.action).value
  const rawProtocol = isKnownProtocol(rule.match?.protocol) ? rule.match.protocol : 'tcp'
  const protocol = getProtocolForAction(action, rawProtocol)
  const responseParams = normalizeResponseParams(action, rule.response?.params)
  const tcpFlags = { ...(rule.match?.tcp_flags || {}) }
  const icmpType = rule.match?.icmp?.type || ''
  const arpOperation = rule.match?.arp?.operation || ''

  if (action === 'tcp_reset') {
    delete tcpFlags.rst
  }

  if (action === 'tcp_syn_ack') {
    tcpFlags.syn = true
    delete tcpFlags.ack
    delete tcpFlags.rst
    delete tcpFlags.fin
    delete tcpFlags.psh
  }

  return {
    ...rule,
    match: {
      protocol,
      vlans: rule.match?.vlans || [],
      src_prefixes: rule.match?.src_prefixes || [],
      dst_prefixes: rule.match?.dst_prefixes || [],
      src_ports: rule.match?.src_ports || [],
      dst_ports: rule.match?.dst_ports || [],
      tcp_flags: tcpFlags,
      icmp: action === 'icmp_echo_reply'
        ? { type: 'echo_request' }
        : protocol === 'icmp' && icmpType
          ? { type: icmpType }
          : null,
      arp: action === 'arp_reply'
        ? { operation: 'request' }
        : protocol === 'arp' && arpOperation
          ? { operation: arpOperation }
          : null,
    },
    response: {
      action,
      params: responseParams,
    },
  }
}

function getActionOption(action) {
  return ACTION_OPTIONS.find(option => option.value === action) || ACTION_OPTIONS[0]
}

function getProtocolForAction(action, currentProtocol = 'tcp') {
  if (UDP_ONLY_ACTIONS.has(action)) {
    return 'udp'
  }

  switch (action) {
    case 'tcp_reset':
    case 'tcp_syn_ack':
      return 'tcp'
    case 'icmp_echo_reply':
      return 'icmp'
    case 'arp_reply':
      return 'arp'
    case 'alert':
    case 'none':
    default:
      return currentProtocol
  }
}

function isProtocolSelectable(action) {
  return action === 'alert' || action === 'none'
}

function isUDPOnlyResponseAction(action) {
  return UDP_ONLY_ACTIONS.has(action)
}

function usesDNSSinkholeParams(action) {
  return action === 'dns_sinkhole'
}

function buildTCPFlags(form) {
  return TCP_FLAG_FIELDS.reduce((flags, field) => {
    if (form[`tcp_flag_${field.key}`]) {
      flags[field.key] = true
    }
    return flags
  }, {})
}

function hasValue(value) {
  return value !== undefined && value !== null && value !== '' && (!Array.isArray(value) || value.length > 0)
}

function validateNumberList(values, min, max, label) {
  const invalid = values.find(value => value < min || value > max)
  if (invalid !== undefined) {
    return `${label} 超出范围: ${invalid}`
  }
  return ''
}

function isBasicIPv4Address(value) {
  const parts = value.split('.')
  if (parts.length !== 4) {
    return false
  }

  return parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
}

function clearTCPFlagsState(form) {
  form.tcp_flag_syn = false
  form.tcp_flag_ack = false
  form.tcp_flag_rst = false
  form.tcp_flag_fin = false
  form.tcp_flag_psh = false
}

export default function RuleForm({ rule, onSubmit, onCancel }) {
  const isNew = !rule
  const initial = normalizeRule(rule)

  const [form, setForm] = useState({
    name: initial.name,
    enabled: initial.enabled,
    priority: initial.priority,
    protocol: initial.match.protocol,
    vlans: joinArr(initial.match.vlans),
    src_prefixes: joinArr(initial.match.src_prefixes),
    dst_prefixes: joinArr(initial.match.dst_prefixes),
    src_ports: joinArr(initial.match.src_ports),
    dst_ports: joinArr(initial.match.dst_ports),
    tcp_flag_syn: Boolean(initial.match.tcp_flags.syn),
    tcp_flag_ack: Boolean(initial.match.tcp_flags.ack),
    tcp_flag_rst: Boolean(initial.match.tcp_flags.rst),
    tcp_flag_fin: Boolean(initial.match.tcp_flags.fin),
    tcp_flag_psh: Boolean(initial.match.tcp_flags.psh),
    icmp_type: initial.match.icmp?.type || '',
    arp_operation: initial.match.arp?.operation || '',
    response_address: initial.response.params.address || '',
    response_ttl: initial.response.params.ttl ?? '',
    action: initial.response.action,
  })
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const isProtocolEditable = isProtocolSelectable(form.action)
  const protocol = form.protocol
  const isTCPProtocol = protocol === 'tcp'
  const isUDPProtocol = protocol === 'udp'
  const isPortProtocol = isTCPProtocol || isUDPProtocol
  const isICMPProtocol = protocol === 'icmp'
  const isARPProtocol = protocol === 'arp'
  const isTCPResetAction = form.action === 'tcp_reset'
  const isICMPPortUnreachableAction = form.action === 'icmp_port_unreachable'
  const isICMPHostUnreachableAction = form.action === 'icmp_host_unreachable'
  const isICMPAdminProhibitedAction = form.action === 'icmp_admin_prohibited'
  const isUDPEchoReplyAction = form.action === 'udp_echo_reply'
  const isDNSRefusedAction = form.action === 'dns_refused'
  const isDNSSinkholeAction = form.action === 'dns_sinkhole'
  const isUDPOnlyAction = isUDPOnlyResponseAction(form.action)
  const isTCPSynAckAction = form.action === 'tcp_syn_ack'
  const isICMPEchoReplyAction = form.action === 'icmp_echo_reply'
  const isARPReplyAction = form.action === 'arp_reply'
  const visibleTCPFlagFields = isTCPSynAckAction ? [{ key: 'syn', label: 'SYN' }] : isTCPResetAction ? TCP_RESET_FLAG_FIELDS : TCP_FLAG_FIELDS

  function set(key, value) {
    setForm(f => {
      if (key === 'action') {
        const nextProtocol = getProtocolForAction(value, f.protocol)
        const next = {
          ...f,
          action: value,
          protocol: nextProtocol,
        }

        if (nextProtocol !== 'tcp') {
          clearTCPFlagsState(next)
        }

        if (value === 'tcp_reset') {
          next.tcp_flag_rst = false
          next.icmp_type = ''
          next.arp_operation = ''
        }

        if (value === 'tcp_syn_ack') {
          clearTCPFlagsState(next)
          next.tcp_flag_syn = true
          next.icmp_type = ''
          next.arp_operation = ''
        }

        if (isUDPOnlyResponseAction(value)) {
          next.icmp_type = ''
          next.arp_operation = ''
          clearTCPFlagsState(next)
        }

        if (value === 'icmp_echo_reply') {
          clearTCPFlagsState(next)
          next.icmp_type = 'echo_request'
          next.arp_operation = ''
        }

        if (value === 'arp_reply') {
          clearTCPFlagsState(next)
          next.arp_operation = 'request'
          next.icmp_type = ''
        }

        if (value === 'alert' || value === 'none') {
          if (nextProtocol !== 'icmp') {
            next.icmp_type = ''
          }
          if (nextProtocol !== 'arp') {
            next.arp_operation = ''
          }
        }

        if (!usesDNSSinkholeParams(value)) {
          next.response_address = ''
          next.response_ttl = ''
        } else if (!next.response_ttl) {
          next.response_ttl = String(DNS_TTL_DEFAULT)
        }

        return next
      }

      if (key !== 'protocol') {
        if (key === 'tcp_flag_rst' && f.action === 'tcp_reset') {
          return f
        }
        if ((key === 'tcp_flag_ack' || key === 'tcp_flag_rst' || key === 'tcp_flag_fin' || key === 'tcp_flag_psh') && f.action === 'tcp_syn_ack') {
          return f
        }
        return { ...f, [key]: value }
      }

      const next = {
        ...f,
        protocol: value,
      }

      if (value !== 'tcp') {
        clearTCPFlagsState(next)
      }

      if (value !== 'icmp') {
        next.icmp_type = ''
      }

      if (value !== 'arp') {
        next.arp_operation = ''
      }

      return next
    })
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')

    if (!form.name.trim()) {
      setError('规则名称不能为空')
      return
    }
    const priority = parseInt(form.priority, 10)
    if (isNaN(priority) || priority < 0) {
      setError('优先级必须为大于等于 0 的整数')
      return
    }

    const vlans = splitNumArr(form.vlans)
    const srcPorts = splitNumArr(form.src_ports)
    const dstPorts = splitNumArr(form.dst_ports)
    const tcpFlags = isTCPProtocol ? buildTCPFlags(form) : {}
    const protocol = form.protocol.trim()
    const action = form.action.trim()
    const responseAddress = form.response_address.trim()
    const responseTTL = form.response_ttl.trim()

    const vlanError = validateNumberList(vlans, 0, 4095, 'VLAN')
    if (vlanError) {
      setError(vlanError)
      return
    }

    const srcPortError = validateNumberList(srcPorts, 1, 65535, '源端口')
    if (srcPortError) {
      setError(srcPortError)
      return
    }

    const dstPortError = validateNumberList(dstPorts, 1, 65535, '目的端口')
    if (dstPortError) {
      setError(dstPortError)
      return
    }

    if (!action) {
      setError('动作类型不能为空')
      return
    }

    if (action === 'icmp_echo_reply') {
      if (protocol !== 'icmp') {
        setError('`icmp_echo_reply` 要求协议为 icmp')
        return
      }
      if (form.icmp_type !== 'echo_request') {
        setError('`icmp_echo_reply` 要求 ICMP 类型为 echo_request')
        return
      }
    }

    if (action === 'arp_reply') {
      if (protocol !== 'arp') {
        setError('`arp_reply` 要求协议为 arp')
        return
      }
      if (form.arp_operation !== 'request') {
        setError('`arp_reply` 要求 ARP 操作为 request')
        return
      }
    }

    if (action === 'tcp_syn_ack') {
      if (protocol !== 'tcp') {
        setError('`tcp_syn_ack` 要求协议为 tcp')
        return
      }
      if (!tcpFlags.syn) {
        setError('`tcp_syn_ack` 要求 TCP Flags 至少选择 SYN')
        return
      }
      if (tcpFlags.ack || tcpFlags.rst || tcpFlags.fin || tcpFlags.psh) {
        setError('`tcp_syn_ack` 仅允许初始 SYN 匹配，不允许 ACK/RST/FIN/PSH')
        return
      }
    }

    if (action === 'tcp_reset' && tcpFlags.rst) {
      setError('`tcp_reset` 不应匹配已带 RST 的报文')
      return
    }

    if (isUDPOnlyResponseAction(action)) {
      if (protocol !== 'udp') {
        setError(`\`${action}\` 要求协议为 udp`)
        return
      }
    }

    if (usesDNSSinkholeParams(action)) {
      if (!responseAddress) {
        setError('`dns_sinkhole` 要求填写 address')
        return
      }
      if (!isBasicIPv4Address(responseAddress)) {
        setError('`dns_sinkhole` 的 address 必须是 IPv4 地址')
        return
      }
      if (responseTTL) {
        const ttl = Number(responseTTL)
        if (!Number.isInteger(ttl) || ttl < 0 || ttl > DNS_TTL_MAX) {
          setError('`dns_sinkhole` 的 ttl 必须是 0 到 2147483647 的整数')
          return
        }
      }
    }

    const match = {
      protocol,
      vlans,
      src_prefixes: normalizePrefixesInput(form.src_prefixes),
      dst_prefixes: normalizePrefixesInput(form.dst_prefixes),
      src_ports: srcPorts,
      dst_ports: dstPorts,
      tcp_flags: tcpFlags,
    }

    if (isICMPProtocol && form.icmp_type) {
      match.icmp = { type: form.icmp_type }
    }

    if (isARPProtocol && form.arp_operation) {
      match.arp = { operation: form.arp_operation }
    }

    const compactMatch = Object.fromEntries(
      Object.entries(match).filter(([, value]) => hasValue(value)),
    )

    const response = { action }
    if (usesDNSSinkholeParams(action)) {
      response.params = { address: responseAddress }
      if (responseTTL) {
        response.params.ttl = Number(responseTTL)
      }
    }

    const payload = {
      name: form.name.trim(),
      enabled: form.enabled,
      priority,
      match: compactMatch,
      response,
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
        <form className="modal-form" onSubmit={handleSubmit}>
          <div className="modal-body">
            {error && <div className="error-msg">{error}</div>}

            <div className="form-section-title">基本信息</div>
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
                <label style={{ marginTop: 22 }}>
                  <span className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={form.enabled}
                      onChange={e => set('enabled', e.target.checked)}
                    />
                    {isNew ? '创建后立即启用' : '启用规则'}
                  </span>
                </label>
              </div>
              <div />
            </div>

            <div className="form-section-title">响应动作</div>
            <div className="form-group">
              <label>动作类型</label>
              <select value={form.action} onChange={e => set('action', e.target.value)}>
                {ACTION_GROUPS.map(group => (
                  <optgroup key={group.label} label={group.label}>
                    {group.options.map(option => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>
              {isUDPOnlyAction && (
                <div className="form-section-desc">该动作会自动固定为 UDP。</div>
              )}
              {isDNSRefusedAction && (
                <div className="form-section-desc">v1 建议额外限制目标端口为 53。</div>
              )}
              {isDNSSinkholeAction && (
                <div className="form-section-desc">v1 仅支持 IPv4 UDP DNS A 查询，返回固定 A 记录。</div>
              )}
            </div>

            {isDNSSinkholeAction && (
              <>
                <div className="form-section-title">响应参数</div>
                <div className="form-row">
                  <div className="form-group">
                    <label>IPv4 Address <span className="required">*</span></label>
                    <input
                      type="text"
                      value={form.response_address}
                      onChange={e => set('response_address', e.target.value)}
                      placeholder="如 192.0.2.10"
                    />
                  </div>
                  <div className="form-group">
                    <label>TTL</label>
                    <input
                      type="number"
                      min="0"
                      max={DNS_TTL_MAX}
                      value={form.response_ttl}
                      onChange={e => set('response_ttl', e.target.value)}
                      placeholder={`默认 ${DNS_TTL_DEFAULT}`}
                    />
                    <div className="form-section-desc">可选，范围 0 到 2147483647。</div>
                  </div>
                </div>
              </>
            )}

            <div className="form-section-title">匹配条件</div>
            <div className="form-section-desc">多个值用英文逗号分隔，留空表示不限制</div>
            <div className="form-row">
              <div className="form-group">
                <label>协议</label>
                {isProtocolEditable ? (
                  <select value={form.protocol} onChange={e => set('protocol', e.target.value)}>
                    {PROTOCOL_OPTIONS.map(option => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input type="text" value={protocol.toUpperCase()} disabled />
                )}
              </div>
              <div className="form-group">
                <label>VLAN</label>
                <input
                  type="text"
                  value={form.vlans}
                  onChange={e => set('vlans', e.target.value)}
                  placeholder="如 100, 200"
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
                  placeholder="如 10.0.0.1 或 10.0.0.0/24"
                />
              </div>
              <div className="form-group">
                <label>目的地址前缀</label>
                <input
                  type="text"
                  value={form.dst_prefixes}
                  onChange={e => set('dst_prefixes', e.target.value)}
                  placeholder="如 192.168.0.1 或 192.168.0.0/24"
                />
              </div>
            </div>
            {isPortProtocol && (
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
            )}
            {isTCPProtocol && (
              <div className="form-row">
                <div className="form-group">
                  <label>TCP Flags</label>
                  <div className="checkbox-group">
                    {visibleTCPFlagFields.map(field => (
                      <label key={field.key} className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={form[`tcp_flag_${field.key}`]}
                          disabled={isTCPSynAckAction && field.key === 'syn'}
                          onChange={e => set(`tcp_flag_${field.key}`, e.target.checked)}
                        />
                        {field.label}
                      </label>
                    ))}
                  </div>
                  {isTCPResetAction && (
                    <div className="form-section-desc">仅匹配未带 RST 的 TCP 报文。</div>
                  )}
                  {isTCPSynAckAction && (
                    <div className="form-section-desc">固定匹配初始 SYN。</div>
                  )}
                </div>
              </div>
            )}
            {(isICMPProtocol || isARPProtocol) && (
              <div className="form-row">
                {isICMPProtocol && (
                  <div className="form-group">
                    <label>ICMP 类型</label>
                    {isICMPEchoReplyAction ? (
                      <input type="text" value="Echo Request" disabled />
                    ) : (
                      <select value={form.icmp_type} onChange={e => set('icmp_type', e.target.value)}>
                        {ICMP_TYPE_OPTIONS.map(option => (
                          <option key={option.value || 'any'} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                )}
                {isARPProtocol && (
                  <div className="form-group">
                    <label>ARP 操作</label>
                    {isARPReplyAction ? (
                      <input type="text" value="Request" disabled />
                    ) : (
                      <select value={form.arp_operation} onChange={e => set('arp_operation', e.target.value)}>
                        {ARP_OPERATION_OPTIONS.map(option => (
                          <option key={option.value || 'any'} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                )}
              </div>
            )}
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
