import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** Cloud Code routes with their actual routing layer. */
export const CLOUD_CODE_ROUTES = [
  { id: 'karing-proxy', kind: 'proxy', name: 'Karing Full Proxy', host: '127.0.0.1', port: 3066, protocol: 'socks5' },
  { id: 'geohide-eu-doh', kind: 'smart-resolver', name: 'GeoHide EU Smart DNS', url: 'https://eu.geohide.ru/dns-query', bootstrapIps: ['5.175.161.3', '5.175.161.40', '37.221.93.141', '37.221.93.128', '45.13.237.213', '31.25.239.132', '143.20.64.192'], region: 'EU', hostnameFirst: true, parallelBootstrap: true },
  { id: 'geohide-us-doh', kind: 'smart-resolver', name: 'GeoHide US Smart DNS', url: 'https://us.geohide.ru/dns-query', bootstrapIps: ['192.255.159.240', '192.255.159.241', '107.175.76.134', '192.3.233.253'], region: 'US' },
  { id: 'geohide-88', kind: 'gateway', name: 'GeoHide SNI #1', host: '193.233.112.88', port: 443 },
  { id: 'geohide-68', kind: 'gateway', name: 'GeoHide SNI #2', host: '193.233.112.68', port: 443 },
  { id: 'geohide-67', kind: 'gateway', name: 'GeoHide SNI #3', host: '193.233.112.67', port: 443 },
  { id: 'xbox-1', kind: 'relay', name: 'Xbox Relay #1', host: '87.228.47.194', port: 443, sni: 'relay.xbox-dns.ru' },
  { id: 'xbox-2', kind: 'relay', name: 'Xbox Relay #2', host: '87.228.47.202', port: 443, sni: 'relay.xbox-dns.ru' },
  { id: 'doh-dns-ai', kind: 'resolver', name: 'DNS-AI', url: 'https://dns.dns-ai.ru/dns-query' },
  { id: 'doh-comss', kind: 'resolver', name: 'Comss.one DNS', url: 'https://dns.comss.one/dns-query' },
  { id: 'doh-router-comss', kind: 'resolver', name: 'Router Comss.one', url: 'https://router.comss.one/dns-query' },
  { id: 'doh-malw', kind: 'resolver', name: 'Malw DNS', url: 'https://dns.malw.link/dns-query' },
  { id: 'doh-bezmezhau', kind: 'resolver', name: 'Bezmezhau DNS', url: 'https://dns.bezmezhau.com/dns-query' },
  { id: 'doh-mafioznik', kind: 'resolver', name: 'Mafioznik DNS', url: 'https://dns.mafioznik.xyz/dns-query' },
  { id: 'doh-astracat', kind: 'resolver', name: 'Astracat DNS', url: 'https://dns.astracat.network/dns-query' },
  { id: 'doh-wlrus', kind: 'resolver', name: 'WLRUS DNS', url: 'https://dns.wlrus.cfd/dns-query' },
  { id: 'doh-shecan', kind: 'resolver', name: 'Shecan DNS', url: 'https://free.shecan.ir/dns-query' },
  { id: 'ag-dns', kind: 'local-proxy', name: 'ag_dns (local)', host: '127.0.0.1' },
]

export const DOH_RESOLVERS = CLOUD_CODE_ROUTES.filter((route) => route.kind === 'resolver')
export const SMART_DOH_ROUTES = CLOUD_CODE_ROUTES.filter((route) => route.kind === 'smart-resolver')

// Try GeoHide US Smart DNS first. Its DNS answers can direct supported domains to GeoHide's US proxy edge.
// Ordinary DoH resolvers remain fallback candidates only; they do not themselves change egress.
export const AUTO_ROUTE_IDS = ['geohide-eu-doh', 'geohide-us-doh', 'doh-comss', 'doh-router-comss', 'doh-bezmezhau', 'doh-wlrus']

const ROUTE_PREFERENCE_PATH = process.env.ANTIGRAVITY_ROUTE_PREFERENCE_PATH || path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'cloudcode-route.json')
const ROUTE_HEALTH_PATH = process.env.ANTIGRAVITY_ROUTE_HEALTH_PATH || path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'cloudcode-route-health.json')
const ROUTE_FAILURE_COOLDOWN_MS = 6 * 60 * 60 * 1000

function isKnownRouteId(routeId) {
  return CLOUD_CODE_ROUTES.some((route) => route.id === routeId)
}

/** Returns confirmed generation rejections kept separately from a transport probe. */
export function readCloudCodeRouteHealth() {
  try {
    const parsed = JSON.parse(fs.readFileSync(ROUTE_HEALTH_PATH, 'utf8').replace(/^\uFEFF/u, ''))
    const locationRejected = Object.fromEntries(
      Object.entries(parsed.locationRejected || {}).filter(([routeId, value]) =>
        isKnownRouteId(routeId) && value && value.reason === 'location-not-supported' && typeof value.at === 'string'
      )
    )
    const now = Date.now()
    const routeFailures = Object.fromEntries(
      Object.entries(parsed.routeFailures || {}).filter(([routeId, value]) => {
        if (!isKnownRouteId(routeId) || !value || value.reason !== 'tls-failed' || typeof value.at !== 'string') return false
        const failedAt = Date.parse(value.at)
        const age = now - failedAt
        return Number.isFinite(failedAt) && age >= -5 * 60 * 1000 && age < ROUTE_FAILURE_COOLDOWN_MS
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
  } else if (tlsFailed) {
    health.routeFailures[routeId] = { reason: 'tls-failed', at: new Date().toISOString() }
  }
  writeCloudCodeRouteHealth(health)
  return health
}

/** Returns the persisted routing preference, defaulting malformed data to Auto. */
export function readCloudCodeRoutePreference() {
  try {
    const parsed = JSON.parse(fs.readFileSync(ROUTE_PREFERENCE_PATH, 'utf8'))
    const route = String(parsed.route || 'auto')
    return route === 'auto' || CLOUD_CODE_ROUTES.some((candidate) => candidate.id === route) ? route : 'auto'
  } catch {
    return 'auto'
  }
}

/** Persists a routing preference only after validating its route id. */
export function writeCloudCodeRoutePreference(route) {
  if (route !== 'auto' && !CLOUD_CODE_ROUTES.some((candidate) => candidate.id === route)) {
    throw new Error('Unknown Cloud Code route preference')
  }
  fs.mkdirSync(path.dirname(ROUTE_PREFERENCE_PATH), { recursive: true })
  fs.writeFileSync(ROUTE_PREFERENCE_PATH, JSON.stringify({ route, updatedAt: new Date().toISOString() }, null, 2) + '\n', 'utf8')
  return { ok: true, route, path: ROUTE_PREFERENCE_PATH }
}

/** Returns UI labels that distinguish a resolver from an egress route. */
export function getCloudCodeRouteOptions() {
  const health = readCloudCodeRouteHealth()
  const suffixFor = (route) => health.locationRejected[route.id]
    ? ' - исключён из Auto: Google отклонил регион'
    : health.routeFailures[route.id]
      ? ' - исключён из Auto на 6 ч: TLS-сбой'
      : ''
  return [
    { id: 'auto', label: 'Авто (GeoHide EU → GeoHide US → Comss.one → Router Comss.one → Bezmezhau → WLRUS)' },
    ...CLOUD_CODE_ROUTES.map((route) => {
      const suffix = suffixFor(route)
      if (route.kind === 'proxy') return { id: route.id, label: `${route.name} — SOCKS5 127.0.0.1:${route.port} (выход через Karing)${suffix}` }
      if (route.kind === 'smart-resolver') return { id: route.id, label: `${route.name} — проксирующий DoH, регион ${route.region || 'unknown'}${suffix}` }
      if (route.kind === 'resolver') return { id: route.id, label: `${route.name} — DoH-резолвер (не egress-прокси)${suffix}` }
      if (route.kind === 'local-proxy') return { id: route.id, label: `ag_dns — локальный прокси (только при безопасном gate)${suffix}` }
      return { id: route.id, label: `${route.name}${suffix}` }
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
  if (preference !== 'auto') {
    const selected = CLOUD_CODE_ROUTES.find((route) => route.id === preference)
    if (!selected) throw new Error(`Unknown Cloud Code route: ${preference}`)
    if (selected.id === 'ag-dns' && !agDnsSafe) throw new Error('Manual ag_dns route is disabled: gate reports RU/direct/unsafe exit')
    return [selected]
  }
  // GeoHide EU Smart DNS is the first candidate from the admin-provided endpoint list; US is second.
  // Ordinary DoH resolvers remain fallback candidates and do not themselves change egress.
  const plan = AUTO_ROUTE_IDS
    .map((routeId) => CLOUD_CODE_ROUTES.find((route) => route.id === routeId))
    .filter((route) => route && !rejected[route.id] && !failed[route.id])
  if (!plan.length) throw new Error('No DoH routes remain in DNS-only Auto after recorded generation rejections/TLS failures; choose a manual route or inspect route health')
  return plan
}
