const BASE = '/api/v1'

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    })
  } catch {
    throw new Error('无法连接到服务端')
  }
  if (res.status === 204) return null
  let body
  try {
    body = await res.json()
  } catch {
    throw new Error(res.ok ? '服务端返回数据格式异常' : `请求失败 (HTTP ${res.status})`)
  }
  if (!res.ok) {
    throw new Error(body.error?.message || `请求失败 (HTTP ${res.status})`)
  }
  return body
}

export async function getStatus() {
  const res = await request('/status')
  return res.data
}

export async function listRules(page = 1, pageSize = 20) {
  const res = await request(`/rules?page=${page}&page_size=${pageSize}`)
  return { rules: res.data, total: res.total, page: res.page, pageSize: res.page_size }
}

export async function getRule(id) {
  const res = await request(`/rules/${id}`)
  return res.data
}

export async function createRule(rule) {
  const res = await request('/rules', {
    method: 'POST',
    body: JSON.stringify(rule),
  })
  return res.data
}

export async function updateRule(id, rule) {
  const res = await request(`/rules/${id}`, {
    method: 'PUT',
    body: JSON.stringify(rule),
  })
  return res.data
}

export async function deleteRule(id) {
  await request(`/rules/${id}`, { method: 'DELETE' })
}

export async function enableRule(id) {
  const res = await request(`/rules/${id}/enable`, { method: 'POST' })
  return res.data
}

export async function disableRule(id) {
  const res = await request(`/rules/${id}/disable`, { method: 'POST' })
  return res.data
}

export async function getStats(window = '') {
  const params = new URLSearchParams()
  if (window) params.set('window', window)
  const query = params.toString() ? `?${params.toString()}` : ''
  const res = await request(`/stats${query}`)
  return res.data
}

export async function getStatsWindows() {
  const res = await request('/stats/windows')
  return res.data
}
