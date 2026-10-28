import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** Cloud Code routes with their actual routing layer. */
export const CLOUD_CODE_ROUTES = [
  { id: 'karing-proxy', kind: 'proxy', name: 'Karing Full Proxy', host: '127.0.0.1', port: 3066, protocol: 'socks5' },
  { id: 'geohide-eu-doh', kind: 'smart-resolver', name: 'GeoHide EU Smart DNS', url: 'https://eu.geohide.ru/dns-query', bootstrapIps: ['5.175.161.3', '5.175.161.40', '37.221.93.141', '37.221.93.128', '45.13.237.213', '31.25.239.132', '143.20.64.192'], region: 'EU', hostnameFirst: true, parallelBootstrap: true },
  { id: 'geohide-us-doh', kind: 'smart-resolver', name: 'GeoHide US Smart DNS', url: 'https://us.geohide.ru/dns-query', bootstrapIps: ['192.255.159.240', '192.255.159.241', '107.175.76.134', '192.3.233.253'], region: 'US' },
  { id: 'direct-system', kind: 'direct-system', name: 'Direct System (VPN/Zapret)' },
  { id: 'ag-dns', kind: 'local-proxy', name: 'ag_dns (local)', host: '127.0.0.1' },
]

export const DOH_RESOLVERS = CLOUD_CODE_ROUTES.filter((route) => route.kind === 'resolver')
export const SMART_DOH_ROUTES = CLOUD_CODE_ROUTES.filter((route) => route.kind === 'smart-resolver')

// Try GeoHide EU Smart DNS first, then GeoHide US, and direct-system for active VPN/Zapret users.
export const AUTO_ROUTE_IDS = ['geohide-eu-doh', 'geohide-us-doh', 'direct-system']

const ROUTE_PREFERENCE_PATH = process.env.ANTIGRAVITY_ROUTE_PREFERENCE_PATH || path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'cloudcode-route.json')
const ROUTE_HEALTH_PATH = process.env.ANTIGRAVITY_ROUTE_HEALTH_PATH || path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'cloudcode-route-health.json')
const CUSTOM_ROUTES_PATH = process.env.ANTIGRAVITY_CUSTOM_ROUTES_PATH || path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'custom-routes.json')
const LOGS_DIR = path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'logs')
const INCIDENT_LOG_PATH = process.env.ANTIGRAVITY_INCIDENT_LOG_PATH || path.join(LOGS_DIR, 'last-incident.json')
const LEGACY_INCIDENT_PATH = path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'last-incident.json')
const INCIDENT_HISTORY_PATH = path.join(LOGS_DIR, 'incident-history.jsonl')
const ROUTE_FAILURE_COOLDOWN_MS = 6 * 60 * 60 * 1000

function getCustomRoutesPath() {
  return process.env.ANTIGRAVITY_CUSTOM_ROUTES_PATH || path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'custom-routes.json')
}

/** Reads user-defined routes from custom-routes.json */
export function readCustomRoutes() {
  const customPath = getCustomRoutesPath()
  try {
    if (!fs.existsSync(customPath)) return []
    const parsed = JSON.parse(fs.readFileSync(customPath, 'utf8').replace(/^\uFEFF/u, ''))
    if (!Array.isArray(parsed)) return []
    return parsed.filter(item => item && typeof item.id === 'string' && typeof item.name === 'string' && typeof item.kind === 'string')
  } catch {
    return []
  }
}

/** Writes user-defined routes to custom-routes.json */
export function writeCustomRoutes(routes) {
  if (!Array.isArray(routes)) throw new Error('Routes must be an array')
  const customPath = getCustomRoutesPath()
  fs.mkdirSync(path.dirname(customPath), { recursive: true })
  fs.writeFileSync(customPath, JSON.stringify(routes, null, 2) + '\n', 'utf8')
  return routes
}

/** Adds or updates a user-defined custom route with strict schema validation */
export function addCustomRoute(entry) {
  if (!entry || typeof entry !== 'object') throw new Error('Invalid route entry')
  const name = String(entry.name || '').trim()
  if (!name) throw new Error('Название маршрута обязательно')
  const kind = String(entry.kind || '').trim().toLowerCase()
  if (!['smart-resolver', 'resolver', 'proxy'].includes(kind)) {
    throw new Error('Недопустимый тип маршрута. Допустимо: smart-resolver, resolver, proxy')
  }

  const rawId = entry.id ? String(entry.id).trim().toLowerCase() : `custom-${Date.now().toString(36)}`
  const id = rawId.replace(/[^a-z0-9_-]/g, '') || `custom-${Date.now().toString(36)}`
  if (CLOUD_CODE_ROUTES.some(r => r.id === id)) {
    throw new Error(`Идентификатор маршрута совпадает со встроенным: ${id}`)
  }

  let route
  if (kind === 'resolver' || kind === 'smart-resolver') {
    let urlStr = String(entry.url || '').trim()
    if (!urlStr) throw new Error('URL адрес DoH сервера обязателен')
    if (!urlStr.startsWith('https://')) {
      if (urlStr.includes('://')) throw new Error('DoH endpoint должен использовать HTTPS')
      urlStr = 'https://' + urlStr
    }
    let u
    try {
      u = new URL(urlStr)
      if (!u.hostname || !u.hostname.includes('.')) throw new Error('Invalid host')
    } catch {
      throw new Error('Некорректный HTTPS URL для DoH сервера')
    }
    if (u.protocol !== 'https:') throw new Error('DoH endpoint должен использовать HTTPS')
    
    let bootstrapIps = []
    if (Array.isArray(entry.bootstrapIps)) {
      bootstrapIps = entry.bootstrapIps.map(ip => String(ip).trim()).filter(ip => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip))
    } else if (typeof entry.bootstrapIps === 'string') {
      bootstrapIps = entry.bootstrapIps.split(',').map(ip => ip.trim()).filter(ip => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip))
    }

    route = {
      id,
      kind,
      name,
      url: u.href,
      bootstrapIps,
      region: entry.region ? String(entry.region).trim().toUpperCase() : (kind === 'smart-resolver' ? 'CUSTOM' : undefined),
      custom: true,
      createdAt: entry.createdAt || new Date().toISOString(),
    }
  } else if (kind === 'proxy') {
    let host = String(entry.host || '127.0.0.1').trim()
    if (host === 'localhost' || host === '::1') host = '127.0.0.1'
    const port = Number(entry.port)
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      throw new Error('Некорректный порт SOCKS5 (1-65535)')
    }
    route = {
      id,
      kind: 'proxy',
      name,
      host,
      port,
      protocol: 'socks5',
      custom: true,
      createdAt: entry.createdAt || new Date().toISOString(),
    }
  }

  const custom = readCustomRoutes().filter(r => r.id !== route.id)
  custom.push(route)
  writeCustomRoutes(custom)
  return route
}

/** Removes a custom route by its unique ID */
export function removeCustomRoute(routeId) {
  if (!routeId) throw new Error('Route ID required')
  if (CLOUD_CODE_ROUTES.some(r => r.id === routeId)) {
    throw new Error('Нельзя удалять встроенный системный маршрут')
  }
  const custom = readCustomRoutes().filter(r => r.id !== routeId)
  writeCustomRoutes(custom)
  // If the active route preference was this removed route, reset to auto
  if (readCloudCodeRoutePreference() === routeId) {
    writeCloudCodeRoutePreference('auto')
  }
  return { ok: true, removed: routeId }
}

/** Returns all active routes: built-in plus user-defined */
export function getAllCloudCodeRoutes() {
  const custom = readCustomRoutes()
  return [...CLOUD_CODE_ROUTES, ...custom]
}

function isKnownRouteId(routeId) {
  return getAllCloudCodeRoutes().some((route) => route.id === routeId)
}

const DIRECT_SYSTEM_FAILURE_COOLDOWN_MS = 45 * 1000

/** Returns confirmed generation rejections kept separately from a transport probe. */
export function readCloudCodeRouteHealth() {
  try {
    const parsed = JSON.parse(fs.readFileSync(ROUTE_HEALTH_PATH, 'utf8').replace(/^\uFEFF/u, ''))
    const now = Date.now()
    const locationRejected = Object.fromEntries(
      Object.entries(parsed.locationRejected || {}).filter(([routeId, value]) => {
        if (!isKnownRouteId(routeId) || !value || value.reason !== 'location-not-supported' || typeof value.at !== 'string') return false
        // direct-system location ban expires quickly (45s) so turning on VPN recovers Auto immediately
        if (routeId === 'direct-system') {
          const atMs = Date.parse(value.at)
          return Number.isFinite(atMs) && (now - atMs < DIRECT_SYSTEM_FAILURE_COOLDOWN_MS)
        }
        return true
      })
    )
    const routeFailures = Object.fromEntries(
      Object.entries(parsed.routeFailures || {}).filter(([routeId, value]) => {
        if (!isKnownRouteId(routeId) || !value || value.reason !== 'tls-failed' || typeof value.at !== 'string') return false
        const failedAt = Date.parse(value.at)
        const age = now - failedAt
        const ttl = routeId === 'direct-system' ? DIRECT_SYSTEM_FAILURE_COOLDOWN_MS : ROUTE_FAILURE_COOLDOWN_MS
        return Number.isFinite(failedAt) && age >= -5 * 60 * 1000 && age < ttl
      }).map(([routeId, value]) => [routeId, { reason: 'tls-failed', at: value.at }])
    )
    return { locationRejected, routeFailures }
  } catch {
    return { locationRejected: {}, routeFailures: {} }
  }
}

function writeCloudCodeRouteHealth(health) {
  fs.mkdirSync(path.dirname(ROUTE_HEALTH_PATH), { recursive: true })
  fs.writeFileSync(ROUTE_HEALTH_PATH, JSON.stringify(health, null, 2) + '\n', 'utf8')
}

/**
 * Records an incident snapshot for automated diagnostics by future AI agents.
 * Strictly avoids logging secrets, OAuth tokens, account credentials, or user prompt text.
 */
export function recordIncidentSnapshot(incident) {
  try {
    const payload = {
      timestamp: new Date().toISOString(),
      event: incident?.event || 'ROUTE_INCIDENT',
      routeId: incident?.routeId || null,
      routeLabel: incident?.routeLabel || null,
      target: incident?.target || 'daily-cloudcode-pa.googleapis.com:443',
      stage: incident?.stage || 'UNKNOWN',
      errorType: incident?.errorType || 'ERROR',
      errorMessage: String(incident?.errorMessage || incident?.error || 'Unknown network error').slice(0, 300),
      suggestedAction: incident?.suggestedAction || null,
      context: incident?.context || {},
    }
    fs.mkdirSync(LOGS_DIR, { recursive: true })
    fs.writeFileSync(INCIDENT_LOG_PATH, JSON.stringify(payload, null, 2) + '\n', 'utf8')
    try { fs.writeFileSync(LEGACY_INCIDENT_PATH, JSON.stringify(payload, null, 2) + '\n', 'utf8') } catch {}
    try { fs.appendFileSync(INCIDENT_HISTORY_PATH, JSON.stringify(payload) + '\n', 'utf8') } catch {}
    return payload
  } catch {
    return null
  }
}

/** Returns the latest incident snapshot if present. */
export function readIncidentSnapshot() {
  try {
    if (fs.existsSync(INCIDENT_LOG_PATH)) {
      return JSON.parse(fs.readFileSync(INCIDENT_LOG_PATH, 'utf8').replace(/^\uFEFF/u, ''))
    }
    if (fs.existsSync(LEGACY_INCIDENT_PATH)) {
      return JSON.parse(fs.readFileSync(LEGACY_INCIDENT_PATH, 'utf8').replace(/^\uFEFF/u, ''))
    }
    return null
  } catch {
    return null
  }
}

/**
 * Records only an actual generation result. A successful availability probe cannot
 * clear a region rejection because Google may accept the two endpoints differently.
 */
export function recordCloudCodeRouteGenerationResult(routeId, result) {
  if (!isKnownRouteId(routeId)) throw new Error('Unknown Cloud Code route result')
  const health = readCloudCodeRouteHealth()
  const description = `${result?.shortStatus || ''} ${result?.status || ''}`.toLowerCase()
  // Only an actual generation result may alter route health. DNS/TCP/CONNECT and availability probes do not.
  const regionRejected = result?.shortStatus === '400 location' || /user location is not supported|location.{0,80}not supported|not supported.{0,80}location/.test(description)
  const tlsFailed = /^(tls\/error|tls failed)$/i.test(String(result?.shortStatus || '').trim()) || /tls\/connection error|tls connection failed/.test(description)
  if (result?.ok === true) {
    delete health.locationRejected[routeId]
    delete health.routeFailures[routeId]
  } else if (regionRejected) {
    health.locationRejected[routeId] = { reason: 'location-not-supported', at: new Date().toISOString() }
    delete health.routeFailures[routeId]
    recordIncidentSnapshot({
      event: 'LOCATION_REJECTED',
      routeId,
      stage: 'GENERATION_HTTP_400',
      errorType: '400_LOCATION_NOT_SUPPORTED',
      errorMessage: result?.status || 'User location is not supported for API use',
      suggestedAction: 'Route excluded from Auto. Rotate to Smart DNS or alternative non-RU egress.',
    })
  } else if (tlsFailed) {
    health.routeFailures[routeId] = { reason: 'tls-failed', at: new Date().toISOString() }
    recordIncidentSnapshot({
      event: 'TLS_GENERATION_FAILED',
      routeId,
      stage: 'TLS_HANDSHAKE_OR_DECRYPT',
      errorType: 'TLS_CONNECTION_ERROR',
      errorMessage: result?.status || 'TLS connection error during generation request',
      suggestedAction: 'Route temporarily suspended for 6h in Auto. Verify if gateway endpoint was blocked or degraded.',
    })
  }
  writeCloudCodeRouteHealth(health)
  return health
}

/** Returns the persisted routing preference, defaulting malformed data to Auto. */
export function readCloudCodeRoutePreference() {
  try {
    const parsed = JSON.parse(fs.readFileSync(ROUTE_PREFERENCE_PATH, 'utf8'))
    const route = String(parsed.route || 'auto')
    return route === 'auto' || getAllCloudCodeRoutes().some((candidate) => candidate.id === route) ? route : 'auto'
  } catch {
    return 'auto'
  }
}

/** Persists a routing preference only after validating its route id. */
export function writeCloudCodeRoutePreference(route) {
  if (route !== 'auto' && !getAllCloudCodeRoutes().some((candidate) => candidate.id === route)) {
    throw new Error('Unknown Cloud Code route preference')
  }
  fs.mkdirSync(path.dirname(ROUTE_PREFERENCE_PATH), { recursive: true })
  fs.writeFileSync(ROUTE_PREFERENCE_PATH, JSON.stringify({ route, updatedAt: new Date().toISOString() }, null, 2) + '\n', 'utf8')
  return { ok: true, route, path: ROUTE_PREFERENCE_PATH }
}

/** Returns UI labels that distinguish a resolver from an egress route. */
export function getCloudCodeRouteOptions() {
  const health = readCloudCodeRouteHealth()
  const allRoutes = getAllCloudCodeRoutes()
  const suffixFor = (route) => health.locationRejected[route.id]
    ? ' - исключён из Auto: Google отклонил регион'
    : health.routeFailures[route.id]
      ? ' - исключён из Auto на 6 ч: TLS-сбой'
      : ''
  return [
    { id: 'auto', label: 'Авто (GeoHide EU → GeoHide US → Direct VPN)' },
    ...allRoutes.map((route) => {
      const suffix = suffixFor(route)
      const customBadge = route.custom ? ' [Свой]' : ''
      if (route.kind === 'proxy') return { id: route.id, label: `${route.name}${customBadge} — SOCKS5 ${route.host}:${route.port}${suffix}` }
      if (route.kind === 'smart-resolver') return { id: route.id, label: `${route.name}${customBadge} — проксирующий DoH, регион ${route.region || 'EU/US'}${suffix}` }
      if (route.kind === 'resolver') return { id: route.id, label: `${route.name}${customBadge} — DoH-резолвер (не egress-прокси)${suffix}` }
      if (route.kind === 'direct-system') return { id: route.id, label: `${route.name} — прямой выход (при активном VPN/Zapret)${suffix}` }
      if (route.kind === 'local-proxy') return { id: route.id, label: `ag_dns — локальный прокси (только при безопасном gate)${suffix}` }
      return { id: route.id, label: `${route.name}${customBadge}${suffix}` }
    }),
  ]
}

/**
 * Selects exactly one manual route or the ordered Auto candidates.
 *
 * @param {string} preference Persisted route selection.
 * @param {boolean} agDnsSafe Whether the local proxy may be used for Cloud Code.
 * @returns {typeof CLOUD_CODE_ROUTES}
 */
export function buildCloudCodeRoutePlan(preference, agDnsSafe, locationRejected = null, routeFailures = null) {
  const health = readCloudCodeRouteHealth()
  const rejected = locationRejected || health.locationRejected
  const failed = routeFailures || health.routeFailures
  const allRoutes = getAllCloudCodeRoutes()
  if (preference !== 'auto') {
    const selected = allRoutes.find((route) => route.id === preference)
    if (!selected) throw new Error(`Unknown Cloud Code route: ${preference}`)
    if (selected.id === 'ag-dns' && !agDnsSafe) throw new Error('Manual ag_dns route is disabled: gate reports RU/direct/unsafe exit')
    return [selected]
  }
  // GeoHide EU Smart DNS is the first candidate from the admin-provided endpoint list; US is second.
  // Ordinary DoH resolvers remain fallback candidates and do not themselves change egress.
  const plan = AUTO_ROUTE_IDS
    .map((routeId) => allRoutes.find((route) => route.id === routeId))
    .filter((route) => route && !rejected[route.id] && !failed[route.id])
  if (!plan.length) throw new Error('No DoH routes remain in DNS-only Auto after recorded generation rejections/TLS failures; choose a manual route or inspect route health')
  return plan
}
