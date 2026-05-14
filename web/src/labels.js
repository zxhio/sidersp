export const ACTION_GROUPS = [
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

export const ACTION_OPTIONS = ACTION_GROUPS.flatMap(group => group.options)

export const EVENT_ACTION_OPTIONS = ACTION_OPTIONS.filter(option => option.value !== 'none')
export const RESPONSE_ACTION_OPTIONS = ACTION_OPTIONS.filter(option => [
  'icmp_echo_reply',
  'arp_reply',
  'tcp_syn_ack',
  'udp_echo_reply',
  'dns_refused',
  'dns_sinkhole',
].includes(option.value))

export const EVENT_OUTCOME_OPTIONS = [
  { value: 'observe', label: '仅观测' },
  { value: 'xdp_tx', label: '原口发送' },
  { value: 'xsk_redirect', label: '已送 XSK' },
  { value: 'redirect_tx', label: '内核重定向发送' },
]

export const EVENT_OUTCOME_HINTS = {
  observe: '规则命中后记录了一条观测事件，原始报文后续按入口失败策略处理。',
  xdp_tx: 'BPF 在内核中构造响应报文，并通过 XDP_TX 从原入接口发出；对应统计页原口发送 / xdp_tx。',
  xsk_redirect: 'BPF 已把原始报文重定向到 XSK；真正的用户态响应发送结果请看响应结果页；对应统计页 response_redirect / xsk_redirected。',
  redirect_tx: 'BPF 在内核中构造响应报文，经 bpf_fib_lookup 后通过 XDP_REDIRECT 提交到配置的出接口；对应统计页 redirect_egress / redirect_tx。',
}

export const RESPONSE_RESULT_OPTIONS = [
  { value: 'sent', label: '已发送' },
  { value: 'failed', label: '失败' },
  { value: 'skipped', label: '已跳过' },
]

export const RESPONSE_TX_BACKEND_OPTIONS = [
  { value: 'afxdp', label: 'AF_XDP 原口响应' },
  { value: 'afpacket', label: 'AF_PACKET 出口响应' },
]

const ACTION_LABELS = Object.fromEntries(ACTION_OPTIONS.map(option => [option.value, option.label]))
const EVENT_OUTCOME_LABELS = Object.fromEntries(EVENT_OUTCOME_OPTIONS.map(option => [option.value, option.label]))
const RESPONSE_RESULT_LABELS = Object.fromEntries(RESPONSE_RESULT_OPTIONS.map(option => [option.value, option.label]))
const RESPONSE_TX_BACKEND_LABELS = Object.fromEntries(RESPONSE_TX_BACKEND_OPTIONS.map(option => [option.value, option.label]))

const PACKET_CONDITION_LABELS = {
  PROTO_TCP: 'TCP',
  PROTO_UDP: 'UDP',
  PROTO_ICMP: 'ICMP',
  PROTO_ARP: 'ARP',
  VLAN: 'VLAN',
  SRC_PREFIX: '源地址',
  DST_PREFIX: '目的地址',
  SRC_PORT: '源端口',
  DST_PORT: '目的端口',
  TCP_SYN: 'SYN',
  TCP_ACK: 'ACK',
  TCP_RST: 'RST',
  TCP_FIN: 'FIN',
  TCP_PSH: 'PSH',
  ICMP_ECHO_REQUEST: 'Echo Request',
  ICMP_ECHO_REPLY: 'Echo Reply',
  ARP_REQUEST: 'ARP Request',
  ARP_REPLY: 'ARP Reply',
  L4_PAYLOAD: '有载荷',
}

export function formatActionLabel(action) {
  return ACTION_LABELS[action] || action || '-'
}

export function formatEventOutcomeLabel(outcome) {
  return EVENT_OUTCOME_LABELS[outcome] || outcome || '-'
}

export function formatResponseResultLabel(result) {
  return RESPONSE_RESULT_LABELS[result] || result || '-'
}

export function formatResponseTXBackendLabel(backend) {
  return RESPONSE_TX_BACKEND_LABELS[backend] || backend || '-'
}

export function formatPacketConditionLabels(raw) {
  if (!raw) return '-'
  return String(raw)
    .split('|')
    .filter(Boolean)
    .map(name => PACKET_CONDITION_LABELS[name] || name)
    .join(' / ')
}
