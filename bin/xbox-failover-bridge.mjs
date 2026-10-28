import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import tls from 'node:tls'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { randomBytes } from 'node:crypto'
import { connectViaSocks5Proxy } from './socks5-proxy.mjs'
import { buildCloudCodeRoutePlan, CLOUD_CODE_ROUTES, SMART_DOH_ROUTES, AUTO_ROUTE_IDS, readCloudCodeRouteHealth, readCloudCodeRoutePreference, recordCloudCodeRouteGenerationResult, recordIncidentSnapshot, readIncidentSnapshot, getAllCloudCodeRoutes, readCustomRoutes } from './cloudcode-route-policy.mjs'

const LISTEN_PORT = Number(process.env.ANTIGRAVITY_BRIDGE_PORT || 53130)
const LEGACY_AG_DNS_PORT = Number(process.env.ANTIGRAVITY_BRIDGE_COMPAT_PORT || 53129)
const LISTEN_HOST = '127.0.0.1'
const BRIDGE_BUILD_ID = 'dsh-antigravity-unified-connect-v7'
const PROXY_PORT_PATH = path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'proxy_port')
const GATE_JSON_PATH = path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'gate.json')

function getAgDnsPort() {
  try {
    if (fs.existsSync(PROXY_PORT_PATH)) {
      const p = parseInt(fs.readFileSync(PROXY_PORT_PATH, 'utf8').trim(), 10)
      if (p > 0 && p < 65536) return p
    }
  } catch {}
  return 47129
}

function describeError(error) {
  return String(error?.message || error || 'Unknown network error')
}

const XBOX_AUTH = 'Basic YWd5X2ZyZWVfdGlyZTpwYXNzd29yZC1mb3ItbW9tJ3MtSGFDS2VSIzIwMjYh'
const XBOX_RELAYS = CLOUD_CODE_ROUTES.filter((route) => route.kind === 'relay')
const GEOHIDE_SNI_IPS = CLOUD_CODE_ROUTES.filter((route) => route.kind === 'gateway').map((route) => route.host)
function buildDohAQuery(host) {
  const id = randomBytes(2).readUInt16BE(0)
  const labels = String(host || '').replace(/\.$/u, '').split('.')
  if (!labels.length || labels.some(label => !label || Buffer.byteLength(label, 'ascii') > 63)) {
    throw new Error(`Invalid DNS name: ${host}`)
  }
  const nameBytes = Buffer.concat([
    ...labels.map(label => Buffer.concat([Buffer.from([Buffer.byteLength(label, 'ascii')]), Buffer.from(label, 'ascii')])),
    Buffer.from([0]),
  ])
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x0100, 2) // recursion desired
  header.writeUInt16BE(1, 4) // QDCOUNT
  const qtype = Buffer.alloc(4)
  qtype.writeUInt16BE(1, 0) // A
  qtype.writeUInt16BE(1, 2) // IN
  return { id, packet: Buffer.concat([header, nameBytes, qtype]) }
}

function skipDnsName(packet, start) {
  let offset = start
  while (offset < packet.length) {
    const len = packet[offset]
    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= packet.length) throw new Error('Malformed compressed DNS name')
      return offset + 2
    }
    if (len === 0) return offset + 1
    if (len & 0xc0) throw new Error('Malformed DNS label')
    offset += len + 1
  }
  throw new Error('Truncated DNS name')
}

function isUsablePublicIPv4(address) {
  if (!net.isIPv4(address)) return false
  const [a, b, c] = address.split('.').map(Number)
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false
  if (a === 169 && b === 254) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  if (a === 100 && b >= 64 && b <= 127) return false
  if (a === 192 && b === 0 && c === 0) return false
  if (a === 192 && b === 0 && c === 2) return false
  if (a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) return false
  if (a === 203 && b === 0 && c === 113) return false
  return true
}

function parseDohAResponse(packet, expectedId) {
  if (!Buffer.isBuffer(packet) || packet.length < 12) throw new Error('Empty/truncated DoH response')
  if (packet.readUInt16BE(0) !== expectedId) throw new Error('DoH response ID mismatch')
  const flags = packet.readUInt16BE(2)
  if ((flags & 0x8000) === 0) throw new Error('DoH returned a non-response DNS packet')
  const rcode = flags & 0x000f
  if (rcode !== 0) throw new Error(`DNS response code ${rcode}`)
  const qdCount = packet.readUInt16BE(4)
  const anCount = packet.readUInt16BE(6)
  let offset = 12
  for (let i = 0; i < qdCount; i++) {
    offset = skipDnsName(packet, offset)
    offset += 4
    if (offset > packet.length) throw new Error('Truncated DNS question')
  }
  const addresses = []
  for (let i = 0; i < anCount; i++) {
    offset = skipDnsName(packet, offset)
    if (offset + 10 > packet.length) throw new Error('Truncated DNS answer')
    const type = packet.readUInt16BE(offset)
    const klass = packet.readUInt16BE(offset + 2)
    const rdLength = packet.readUInt16BE(offset + 8)
    offset += 10
    if (offset + rdLength > packet.length) throw new Error('Truncated DNS RDATA')
    if (klass === 1 && type === 1 && rdLength === 4) {
      const address = [...packet.subarray(offset, offset + 4)].join('.')
      if (isUsablePublicIPv4(address)) addresses.push(address)
    }
    offset += rdLength
  }
  return [...new Set(addresses)]
}

function getDohBootstrapHosts(resolver, endpoint) {
  const hosts = Array.isArray(resolver.bootstrapIps) && resolver.bootstrapIps.length
    ? [...resolver.bootstrapIps]
    : [endpoint.hostname]
  if (resolver.hostnameFirst && !hosts.includes(endpoint.hostname)) hosts.unshift(endpoint.hostname)
  return [...new Set(hosts)]
}

async function queryDohWireA(resolver, host, timeoutMs = 2200) {
  let query
  let endpoint
  try {
    query = buildDohAQuery(host)
    endpoint = new URL(resolver.url)
    if (endpoint.protocol !== 'https:') throw new Error('DoH endpoint must use HTTPS')
  } catch (err) {
    throw err
  }
  const bootstrapIps = getDohBootstrapHosts(resolver, endpoint)
  let lastError = null
  for (const connectHost of bootstrapIps) {
    try {
      return await new Promise((resolve, reject) => {
        const requestOptions = {
          hostname: connectHost,
          port: endpoint.port || 443,
          path: `${endpoint.pathname}${endpoint.search}`,
          method: 'POST',
          headers: {
            Host: endpoint.host,
            'Content-Type': 'application/dns-message',
            Accept: 'application/dns-message',
            'Content-Length': query.packet.length,
            'User-Agent': 'dsh-plugin-antigravity-quota/1.5.1',
          },
          timeout: timeoutMs,
        }
        // Bootstrap by IPv4 while retaining TLS SNI and certificate validation for us.geohide.ru.
        if (connectHost !== endpoint.hostname) requestOptions.servername = endpoint.hostname
        let settled = false
        let hardTimer = null
        const finish = (error, value) => {
          if (settled) return
          settled = true
          if (hardTimer) clearTimeout(hardTimer)
          if (error) reject(error)
          else resolve(value)
        }
        const req = https.request(requestOptions, (res) => {
          const chunks = []
          let size = 0
          res.on('data', chunk => {
            size += chunk.length
            if (size > 65536) {
              req.destroy(new Error('DoH response exceeded 64 KiB'))
              finish(new Error('DoH response exceeded 64 KiB'))
              return
            }
            chunks.push(chunk)
          })
          res.on('error', (error) => finish(error))
          res.on('end', () => {
            if (res.statusCode < 200 || res.statusCode >= 300) {
              finish(new Error(`${resolver.name} DoH HTTP ${res.statusCode || 0} via ${connectHost}`))
              return
            }
            try {
              const addresses = parseDohAResponse(Buffer.concat(chunks), query.id)
              if (!addresses.length) throw new Error(`${resolver.name} returned no A records for ${host} via ${connectHost}`)
              finish(null, addresses)
            } catch (err) { finish(err) }
          })
        })
        hardTimer = setTimeout(() => {
          const error = new Error(`${resolver.name} DoH hard timeout via ${connectHost}`)
          req.destroy(error)
          finish(error)
        }, timeoutMs + 250)
        hardTimer.unref?.()
        req.on('timeout', () => req.destroy(new Error(`${resolver.name} DoH timeout via ${connectHost}`)))
        req.on('error', (error) => finish(error))
        req.end(query.packet)
      })
    } catch (error) {
      lastError = error
    }
  }
  throw new Error(`${resolver.name} DoH wire failed: ${describeError(lastError)}`)
}

async function queryDohJsonA(resolver, host, timeoutMs = 2200) {
  let endpoint
  try {
    endpoint = new URL(resolver.url)
    endpoint.searchParams.set('name', host)
    endpoint.searchParams.set('type', 'A')
    if (endpoint.protocol !== 'https:') throw new Error('DoH endpoint must use HTTPS')
  } catch (err) { throw err }
  const bootstrapIps = getDohBootstrapHosts(resolver, endpoint)
  let lastError = null
  for (const connectHost of bootstrapIps) {
    try {
      return await new Promise((resolve, reject) => {
        const requestOptions = {
          hostname: connectHost,
          port: endpoint.port || 443,
          path: `${endpoint.pathname}${endpoint.search}`,
          method: 'GET',
          headers: { Host: endpoint.host, Accept: 'application/dns-json, application/json', 'User-Agent': 'dsh-plugin-antigravity-quota/1.5.1' },
          timeout: timeoutMs,
        }
        if (connectHost !== endpoint.hostname) requestOptions.servername = endpoint.hostname
        let settled = false
        let hardTimer = null
        const finish = (error, value) => {
          if (settled) return
          settled = true
          if (hardTimer) clearTimeout(hardTimer)
          if (error) reject(error)
          else resolve(value)
        }
        const req = https.request(requestOptions, (res) => {
          const chunks = []
          let size = 0
          res.on('data', chunk => {
            size += chunk.length
            if (size > 65536) {
              req.destroy(new Error('DoH JSON response exceeded 64 KiB'))
              finish(new Error('DoH JSON response exceeded 64 KiB'))
              return
            }
            chunks.push(chunk)
          })
          res.on('error', (error) => finish(error))
          res.on('end', () => {
            if (res.statusCode < 200 || res.statusCode >= 300) { finish(new Error(`${resolver.name} DoH JSON HTTP ${res.statusCode || 0} via ${connectHost}`)); return }
            try {
              const data = JSON.parse(Buffer.concat(chunks).toString('utf8'))
              if (data.Status && data.Status !== 0) throw new Error(`DNS response code ${data.Status}`)
              const addresses = [...new Set((data.Answer || []).filter(a => Number(a.type) === 1 && typeof a.data === 'string').map(a => a.data).filter(isUsablePublicIPv4))]
              if (!addresses.length) throw new Error(`${resolver.name} returned no A records for ${host} via ${connectHost}`)
              finish(null, addresses)
            } catch (err) { finish(err) }
          })
        })
        hardTimer = setTimeout(() => {
          const error = new Error(`${resolver.name} DoH JSON hard timeout via ${connectHost}`)
          req.destroy(error)
          finish(error)
        }, timeoutMs + 250)
        hardTimer.unref?.()
        req.on('timeout', () => req.destroy(new Error(`${resolver.name} DoH JSON timeout via ${connectHost}`)))
        req.on('error', (error) => finish(error))
        req.end()
      })
    } catch (error) {
      lastError = error
    }
  }
  throw new Error(`${resolver.name} DoH JSON failed: ${describeError(lastError)}`)
}

async function queryDohA(resolver, host, timeoutMs = 2200) {
  // For the EU endpoint, race the admin-provided bootstrap IPs and the endpoint hostname.
  // A dead candidate must not serially delay all other candidates; choose a response that returns a known GeoHide edge when available.
  if (resolver.parallelBootstrap === true && Array.isArray(resolver.bootstrapIps) && resolver.bootstrapIps.length > 1) {
    const endpoint = new URL(resolver.url)
    const candidates = getDohBootstrapHosts(resolver, endpoint)
    const attempts = await Promise.allSettled(candidates.map(async (candidate) => {
      const single = { ...resolver, bootstrapIps: [candidate], hostnameFirst: false, parallelBootstrap: false }
      return { candidate, addresses: await queryDohA(single, host, timeoutMs) }
    }))
    const successes = attempts.filter((item) => item.status === 'fulfilled').map((item) => item.value)
    if (successes.length) {
      const proxyAnswer = successes.find((item) => item.addresses.some((address) => GEOHIDE_KNOWN_NODE_IPS.has(address)))
      return (proxyAnswer || successes[0]).addresses
    }
    const details = attempts.map((item, index) => `${candidates[index]}: ${describeError(item.reason)}`).slice(0, 4).join('; ')
    throw new Error(`${resolver.name} DoH failed on all bootstrap candidates: ${details}`)
  }
  try {
    return await queryDohWireA(resolver, host, timeoutMs)
  } catch (wireError) {
    try {
      return await queryDohJsonA(resolver, host, timeoutMs)
    } catch (jsonError) {
      throw new Error(`${resolver.name} DoH failed (wire: ${describeError(wireError)}; JSON: ${describeError(jsonError)})`)
    }
  }
}

function connectDirectAddress(address, port = 443, timeoutMs = 1600) {
  return new Promise((resolve, reject) => {
    let settled = false
    const socket = net.connect({ host: address, port })
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      socket.destroy()
      reject(new Error(`TCP timeout ${address}:${port}`))
    }, timeoutMs)
    socket.once('connect', () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.setKeepAlive(true, 15000)
      resolve(socket)
    })
    socket.once('error', err => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      reject(err)
    })
  })
}

async function connectViaDohResolver(resolver, targetHost, targetPort = 443, timeoutMs = 2200, setRouteLabel = null) {
  const addresses = await queryDohA(resolver, targetHost, timeoutMs)
  let lastError = null
  for (const address of addresses.slice(0, 3)) {
    try {
      const socket = await connectDirectAddress(address, targetPort, 1600)
      socket.__dohResolver = resolver.id
      socket.__dohAddresses = addresses
      socket.__routeAddress = address
      if (typeof setRouteLabel === 'function') setRouteLabel(`DoH ${resolver.name} (${address})`)
      return socket
    } catch (err) {
      lastError = err
    }
  }
  throw new Error(`${resolver.name}: DNS [${addresses.join(', ')}], TCP failed: ${lastError?.message || 'no reachable A address'}`)
}

let lastTransportRoute = null
let lastApiResult = null
let lastRouteFailure = null
let lastDiagnosticConnect = null
const diagnosticRoutes = new Map()

function recordTransportRoute(route, socket, diagnosticId = null) {
  const label = route.kind === 'proxy'
    ? `${route.name} (SOCKS5 ${route.host}:${route.port})`
    : route.kind === 'smart-resolver'
      ? `${route.name} (${socket.__routeAddress || 'proxy address pending'})`
      : route.kind === 'resolver'
        ? `DoH ${route.name} (${socket.__routeAddress || 'resolved address'})`
      : route.kind === 'local-proxy'
        ? `ag_dns.exe (127.0.0.1:${getAgDnsPort()})`
        : route.kind === 'relay'
          ? `${route.name} (${route.host})`
          : `geohide-sni (${route.host})`
  const routingEffect = route.kind === 'proxy' ? 'egress-karing-proxy' : route.kind === 'smart-resolver' ? 'geohide-us-smart-dns-proxy' : route.kind === 'resolver' ? 'dns-only' : route.kind === 'relay' ? 'egress-relay' : route.kind === 'gateway' ? 'geohide-gateway' : 'local-proxy'
  lastTransportRoute = { id: route.id, kind: route.kind, routingEffect, label, at: new Date().toISOString() }
  if (socket) socket.__antigravityRouteInfo = { ...lastTransportRoute }
  if (typeof diagnosticId === 'string' && /^[a-zA-Z0-9_-]{12,64}$/u.test(diagnosticId)) {
    diagnosticRoutes.set(diagnosticId, { ...lastTransportRoute })
    while (diagnosticRoutes.size > 100) diagnosticRoutes.delete(diagnosticRoutes.keys().next().value)
  }
  lastRouteFailure = null
}

function recordRouteFailure(route, error) {
  lastRouteFailure = {
    id: route.id,
    message: String(error?.message || error).slice(0, 300),
    at: new Date().toISOString(),
  }
  recordIncidentSnapshot({
    event: 'ROUTE_CONNECTION_FAILED',
    routeId: route?.id || null,
    routeLabel: route?.name || null,
    target: 'daily-cloudcode-pa.googleapis.com:443',
    stage: 'ESTABLISH_FAILOVER_TUNNEL',
    errorType: error?.code || 'TCP_CONNECT_OR_TLS_FAIL',
    errorMessage: describeError(error),
    suggestedAction: `Connection to route ${route?.id} failed. Rotating to subsequent candidate in failover plan.`,
  })
}

function isAgDnsSafeToUse() {
  try {
    if (!fs.existsSync(GATE_JSON_PATH)) return false
    const gate = JSON.parse(fs.readFileSync(GATE_JSON_PATH, 'utf8'))
    // A Russian exit previously caused Google location rejection. Keep ag_dns out of Cloud Code routing in that state.
    const route = String(gate.route || '').toLowerCase()
    const exit = String(gate.vpn_exit || '').trim().toUpperCase()
    if (gate.stood_down || route === 'напрямую' || /direct|напрям|рѕр°рїс/.test(route) || /^(RU|RUSSIA|RUSSIAN)$/.test(exit)) {
      return false
    }
    return true
  } catch {
    return false
  }
}

function connectViaKaringProxy(route, targetHostPort, timeoutMs = 4000) {
  const separator = targetHostPort.lastIndexOf(':')
  if (separator <= 0) throw new Error('Invalid target for Karing proxy')
  const targetHost = targetHostPort.slice(0, separator)
  const targetPort = Number(targetHostPort.slice(separator + 1))
  return connectViaSocks5Proxy(route.host, route.port, targetHost, targetPort, timeoutMs)
}

function connectViaXboxRelay(relay, targetHostPort, timeoutMs = 4500) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect(
      {
        host: relay.host,
        port: relay.port,
        servername: relay.sni,
        rejectUnauthorized: false,
      },
      () => {
        sock.setKeepAlive(true, 15000)
        sock.write(
          [
            `CONNECT ${targetHostPort} HTTP/1.1`,
            `Host: ${targetHostPort}`,
            `Proxy-Authorization: ${XBOX_AUTH}`,
            'Proxy-Connection: keep-alive',
            '',
            '',
          ].join('\r\n')
        )
      }
    )

    const timer = setTimeout(() => {
      sock.destroy()
      reject(new Error(`Timeout connecting to ${relay.name}`))
    }, timeoutMs)

    sock.once('data', (chunk) => {
      clearTimeout(timer)
      const text = chunk.toString('utf8')
      const statusLine = text.split('\r\n')[0] || ''
      if (statusLine.includes(' 200 ')) {
        resolve(sock)
      } else {
        sock.destroy()
        reject(new Error(`${relay.name} rejected CONNECT: ${statusLine}`))
      }
    })

    sock.once('error', (err) => {
      clearTimeout(timer)
      sock.destroy()
      reject(err)
    })
  })
}

function connectViaAgDns(targetHostPort, timeoutMs = 2500) {
  const agPort = getAgDnsPort()
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: '127.0.0.1', port: agPort }, () => {
      sock.setKeepAlive(true, 15000)
      sock.write(`CONNECT ${targetHostPort} HTTP/1.1\r\nHost: ${targetHostPort}\r\n\r\n`)
    })

    const timer = setTimeout(() => {
      sock.destroy()
      reject(new Error(`Timeout connecting to ag_dns:${agPort}`))
    }, timeoutMs)

    sock.once('data', (chunk) => {
      clearTimeout(timer)
      const statusLine = chunk.toString('utf8').split('\r\n')[0] || ''
      if (statusLine.includes(' 200 ')) {
        resolve(sock)
      } else {
        sock.destroy()
        reject(new Error(`ag_dns:${agPort} rejected CONNECT: ${statusLine}`))
      }
    })

    sock.once('error', (err) => {
      clearTimeout(timer)
      sock.destroy()
      reject(err)
    })
  })
}

function connectViaGeoHideSni(ip, targetPort = 443, timeoutMs = 3500) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host: ip, port: targetPort }, () => {
      clearTimeout(timer)
      sock.setKeepAlive(true, 15000)
      resolve(sock)
    })

    const timer = setTimeout(() => {
      sock.destroy()
      reject(new Error(`Timeout connecting to GeoHide ${ip}`))
    }, timeoutMs)

    sock.once('error', (err) => {
      clearTimeout(timer)
      sock.destroy()
      reject(err)
    })
  })
}

async function establishFailoverTunnel(targetHostPort, diagnosticId = null) {
  const [host, portStr] = targetHostPort.split(':')
  const port = Number(portStr) || 443
  // Direct OAuth / Google auth route: use the working system network path for these hosts.
  // OAuth token/userinfo endpoints must not be forced through CloudCode-only relays.
  if (
    port === 443 &&
    ['oauth2.googleapis.com', 'www.googleapis.com', 'openidconnect.googleapis.com'].includes(
      host.toLowerCase().replace(/\.$/u, '')
    )
  ) {
    try {
      const directSocket = await new Promise((resolve, reject) => {
        let settled = false
        const socket = net.connect({ host, port })
        const timer = setTimeout(() => {
          if (settled) return
          settled = true
          socket.destroy()
          reject(new Error('Direct connection timed out to ' + host + ':' + port))
        }, 5000)
        socket.once('connect', () => {
          if (settled) return
          settled = true
          clearTimeout(timer)
          socket.setKeepAlive(true, 15000)
          resolve(socket)
        })
        socket.once('error', (err) => {
          if (settled) return
          settled = true
          clearTimeout(timer)
          socket.destroy()
          reject(err)
        })
      })
      // OAuth traffic must not overwrite the route shown for Cloud Code in /status.
      return directSocket
    } catch {}
  }
  const isGoogleDomain =
    host.endsWith('.googleapis.com') ||
    host.endsWith('.google.com') ||
    host.includes('cloudcode')

  // Non-Google background traffic does not participate in Cloud Code route state.
  if (!isGoogleDomain) {
    return new Promise((resolve, reject) => {
      const s = net.connect({ host, port }, () => resolve(s))
      s.setTimeout(4000, () => { s.destroy(); reject(new Error('Direct connect timeout')) })
      s.once('error', reject)
    })
  }

  // Manual mode makes exactly one attempt. Auto follows the ordered route plan; GeoHide US Smart DNS may return a proxy edge while ordinary DoH only resolves DNS.
  if (
    port === 443 &&
    ['daily-cloudcode-pa.googleapis.com', 'daily-cloudcode-pa.sandbox.googleapis.com', 'cloudcode-pa.googleapis.com'].includes(String(host || '').toLowerCase().replace(/\.$/u, ''))
  ) {
    const preference = readCloudCodeRoutePreference()
    const plan = buildCloudCodeRoutePlan(preference, isAgDnsSafeToUse())
    let lastCloudCodeError = null
    for (const route of plan) {
      try {
        let socket
        if (route.kind === 'proxy') socket = await connectViaKaringProxy(route, targetHostPort, 4000)
        else if (route.kind === 'gateway') socket = await connectViaGeoHideSni(route.host, 443, 2200)
        else if (route.kind === 'resolver' || route.kind === 'smart-resolver') socket = await connectViaDohResolver(route, host, port, route.kind === 'smart-resolver' ? 4500 : 3000)
        else if (route.kind === 'relay') socket = await connectViaXboxRelay(route, targetHostPort, 3000)
        else if (route.kind === 'local-proxy') socket = await connectViaAgDns(targetHostPort, 2200)
        else throw new Error(`Unsupported Cloud Code route kind: ${route.kind}`)
        recordTransportRoute(route, socket, diagnosticId)
        return socket
      } catch (error) {
        recordRouteFailure(route, error)
        lastCloudCodeError = error
        if (preference !== 'auto') throw new Error(`Manual route ${preference} failed: ${error.message}`)
      }
    }
    throw new Error('No Cloud Code route could be established: ' + (lastCloudCodeError?.message || 'GeoHide, DoH, Xbox and safe ag_dns routes failed'))
  }
  // 1. Primary: Local ag_dns.exe if safe to use (2ms ultra-low latency)
  if (isAgDnsSafeToUse()) {
    try {
      return await connectViaAgDns(targetHostPort, 1500)
    } catch {}
  }

  // 2. Secondary: GeoHide SNI gateways for Google CloudCode domains (18ms latency)
  if (port === 443 && (host === 'daily-cloudcode-pa.googleapis.com' || host === 'cloudcode-pa.googleapis.com')) {
    for (const ip of GEOHIDE_SNI_IPS) {
      try {
        return await connectViaGeoHideSni(ip, 443, 2000)
      } catch {}
    }
  }

  // 3. Tertiary: Xbox DNS Relays (with 2s timeout per relay)
  for (const relay of XBOX_RELAYS) {
    try {
      return await connectViaXboxRelay(relay, targetHostPort, 2000)
    } catch {}
  }

  // 4. Fallback attempt via local ag_dns
  return connectViaAgDns(targetHostPort, 2500)
}

function bridgeStatus() {
  return {
    ok: true,
    port: LISTEN_PORT,
    bridgeBuildId: BRIDGE_BUILD_ID,
    routePreference: readCloudCodeRoutePreference(),
    autoRouteIds: [...AUTO_ROUTE_IDS],
    locationRejectedRouteIds: Object.keys(readCloudCodeRouteHealth().locationRejected),
    temporarilyFailedRouteIds: Object.keys(readCloudCodeRouteHealth().routeFailures),
    activeRoute: lastTransportRoute?.label || null,
    activeRouteId: lastTransportRoute?.id || null,
    lastTransportRoute,
    lastApiResult,
    lastRouteFailure,
    lastDiagnosticConnect,
    agDnsSafe: isAgDnsSafeToUse(),
    lastIncident: readIncidentSnapshot(),
  }
}

function readReportBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > 4096) {
        reject(new Error('Route report exceeds 4 KiB'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))) }
      catch { reject(new Error('Invalid route report JSON')) }
    })
    req.on('error', reject)
  })
}

const GEOHIDE_US_PROBE_HOST = 'daily-cloudcode-pa.googleapis.com'
const GEOHIDE_KNOWN_NODE_IPS = new Set([
  '192.255.159.241', '107.175.76.134', '192.255.159.240', '192.3.233.253',
  '159.194.200.33', '193.233.112.67', '193.233.112.68', '193.233.112.88',
  '45.155.204.190', '37.230.192.51', '46.8.158.6', '5.175.161.3',
  '5.175.161.40', '37.221.93.141', '37.221.93.128', '45.13.237.213',
  '31.25.239.132', '143.20.64.192',
])

function probeTlsSni(address, hostname, timeoutMs = 2200) {
  return new Promise((resolve) => {
    let settled = false
    const finish = (result, socket = null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { socket?.destroy() } catch {}
      resolve(result)
    }
    const socket = tls.connect({ host: address, port: 443, servername: hostname, rejectUnauthorized: true })
    const timer = setTimeout(() => finish({ address, ok: false, error: 'TLS handshake timeout' }, socket), timeoutMs)
    socket.once('secureConnect', () => finish({ address, ok: socket.authorized === true, authorized: socket.authorized === true, error: socket.authorized ? null : String(socket.authorizationError || 'TLS certificate validation failed') }, socket))
    socket.once('error', (error) => finish({ address, ok: false, error: describeError(error).slice(0, 180) }, socket))
  })
}

function timedOutGeoHideProbe(route, results = []) {
  return {
    ok: false,
    routeId: route.id,
    routeName: route.name,
    endpoint: route.url,
    target: GEOHIDE_US_PROBE_HOST,
    noApiRequestSent: true,
    dnsAvailable: results.some((item) => item.ok),
    smartProxyDetected: false,
    tlsOk: false,
    timedOut: true,
    assessment: `${route.name} probe exceeded its 12-second safety deadline; no Google API request was sent.`,
    results,
    tlsChecks: [],
    at: new Date().toISOString(),
  }
}

async function probeGeoHideSmartDoh(routeId) {
  const allRoutes = getAllCloudCodeRoutes()
  const route = allRoutes.find((item) => item.id === routeId)
  if (!route) throw new Error(`GeoHide Smart DNS route is not configured: ${routeId}`)
  const runProbe = async () => {
    const endpointHost = new URL(route.url).hostname
    const probeCandidates = [...new Set([...route.bootstrapIps, endpointHost])]
    const results = await Promise.all(probeCandidates.map(async (dnsServer) => {
      try {
        const resolver = { ...route, bootstrapIps: [dnsServer], hostnameFirst: false, parallelBootstrap: false }
        // A probe is read-only; short per-transport deadlines ensure dead IPs cannot stall the UI.
        const addresses = await queryDohA(resolver, GEOHIDE_US_PROBE_HOST, 1500)
        return {
          dnsServer,
          ok: true,
          addresses,
          knownGeoHideProxyAddress: addresses.some((address) => GEOHIDE_KNOWN_NODE_IPS.has(address)),
          error: null,
        }
      } catch (error) {
        return { dnsServer, ok: false, addresses: [], knownGeoHideProxyAddress: false, error: describeError(error).slice(0, 220) }
      }
    }))
    const proxyAddresses = [...new Set(results.flatMap((result) => result.addresses).filter((address) => GEOHIDE_KNOWN_NODE_IPS.has(address)))].slice(0, 4)
    const tlsChecks = await Promise.all(proxyAddresses.map((address) => probeTlsSni(address, GEOHIDE_US_PROBE_HOST, 1800)))
    const dnsAvailable = results.some((result) => result.ok)
    const smartProxyDetected = results.some((result) => result.knownGeoHideProxyAddress)
    const tlsOk = tlsChecks.some((result) => result.ok)
    let assessment
    if (!dnsAvailable) assessment = `${route.name} did not answer via any supplied IP. The listed IPs may be proxy nodes rather than active DoH listeners.`
    else if (!smartProxyDetected) assessment = 'DoH answered, but Cloud Code did not resolve to a recognized GeoHide proxy node; smart-proxy routing is not confirmed.'
    else if (tlsOk) assessment = 'A recognized GeoHide proxy node was returned and TLS/SNI succeeded. No Google API generation request was sent.'
    else assessment = 'A recognized GeoHide proxy node was returned, but TLS/SNI did not succeed. No Google API generation request was sent.'
    return {
      ok: dnsAvailable,
      routeId: route.id,
      routeName: route.name,
      endpoint: route.url,
      target: GEOHIDE_US_PROBE_HOST,
      noApiRequestSent: true,
      dnsAvailable,
      smartProxyDetected,
      tlsOk,
      timedOut: false,
      assessment,
      results,
      tlsChecks,
      at: new Date().toISOString(),
    }
  }
  let guard
  const timeout = new Promise((resolve) => {
    guard = setTimeout(() => resolve(timedOutGeoHideProbe(route)), 12000)
    guard.unref?.()
  })
  try {
    return await Promise.race([runProbe().catch((error) => ({
      ok: false, routeId: route.id, routeName: route.name, endpoint: route.url,
      target: GEOHIDE_US_PROBE_HOST, noApiRequestSent: true, dnsAvailable: false,
      smartProxyDetected: false, tlsOk: false, timedOut: false,
      assessment: describeError(error).slice(0, 240), results: [], tlsChecks: [], at: new Date().toISOString(),
    })), timeout])
  } finally {
    clearTimeout(guard)
  }
}

const server = http.createServer(async (req, res) => {
  // CSRF protection: block cross-origin browser requests from external websites to local bridge endpoints
  const origin = req.headers['origin']
  const secFetchSite = req.headers['sec-fetch-site']
  if (origin || (secFetchSite && secFetchSite !== 'none' && secFetchSite !== 'same-origin')) {
    res.writeHead(403, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: false, error: 'Cross-origin browser requests to local bridge are forbidden' }))
    return
  }

  if (req.method === 'POST' && req.url === '/route-result') {
    try {
      const report = await readReportBody(req)
      let routeRecord = null
      const diagnosticId = typeof report.diagnosticId === 'string' && /^[a-zA-Z0-9_-]{12,64}$/u.test(report.diagnosticId)
        ? report.diagnosticId
        : null
      if (diagnosticId) {
        routeRecord = diagnosticRoutes.get(diagnosticId) || null
        if (!routeRecord) throw new Error('Diagnostic route correlation was not found')
        if (report.routeId && report.routeId !== routeRecord.id) throw new Error('Route report does not match its diagnostic tunnel')
      } else {
        if (!lastTransportRoute || report.routeId !== lastTransportRoute.id) throw new Error('Route report does not match the latest tunnel')
        routeRecord = lastTransportRoute
      }
      lastApiResult = {
        routeId: routeRecord.id,
        routeKind: routeRecord.kind,
        routingEffect: routeRecord.routingEffect,
        routeLabel: routeRecord.label,
        ok: report.ok === true,
        stage: report.stage === 'generation' ? 'generation' : 'availability',
        shortStatus: String(report.shortStatus || 'Unknown').slice(0, 80),
        status: String(report.status || 'No status').slice(0, 240),
        at: new Date().toISOString(),
      }
      if (lastApiResult.stage === 'generation') {
        recordCloudCodeRouteGenerationResult(lastApiResult.routeId, lastApiResult)
      }
      if (diagnosticId) diagnosticRoutes.delete(diagnosticId)
      res.writeHead(204)
      res.end()
    } catch (error) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: String(error.message || error).slice(0, 160) }))
    }
    return
  }
  if (req.method === 'GET' && req.url?.startsWith('/diagnostic-route?')) {
    try {
      const parsedUrl = new URL(req.url, 'http://127.0.0.1')
      const diagnosticId = parsedUrl.searchParams.get('id') || ''
      if (!/^[a-zA-Z0-9_-]{12,64}$/u.test(diagnosticId)) throw new Error('Invalid diagnostic id')
      const routeRecord = diagnosticRoutes.get(diagnosticId)
      if (!routeRecord) throw new Error('Diagnostic route correlation was not found')
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      res.end(JSON.stringify({ ok: true, route: routeRecord }))
    } catch (error) {
      res.writeHead(404, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      res.end(JSON.stringify({ ok: false, error: String(error.message || error).slice(0, 120) }))
    }
    return
  }
  if (req.method === 'GET' && (req.url === '/geohide-us-doh-probe' || req.url === '/geohide-eu-doh-probe')) {
    const routeId = req.url === '/geohide-eu-doh-probe' ? 'geohide-eu-doh' : 'geohide-us-doh'
    try {
      const result = await probeGeoHideSmartDoh(routeId)
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      res.end(JSON.stringify(result))
    } catch (error) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      res.end(JSON.stringify({ ok: false, routeId, noApiRequestSent: true, timedOut: false, error: describeError(error).slice(0, 200) }))
    }
    return
  }
  if (req.url === '/healthz' || req.url === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(bridgeStatus()))
    return
  }
  if (req.url === '/last-incident') {
    const inc = readIncidentSnapshot()
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify({ ok: true, incident: inc }))
    return
  }
  res.writeHead(200, { 'Content-Type': 'text/plain' })
  res.end(`Antigravity Cloud Code Bridge active (${lastTransportRoute?.label || 'no Cloud Code tunnel yet'})`)
})

server.on('connect', async (req, clientSocket, head) => {
  clientSocket.on('error', () => {})
  const rawDiagnosticId = req.headers['x-antigravity-diagnostic-id']
  const diagnosticId = typeof rawDiagnosticId === 'string' && /^[a-zA-Z0-9_-]{12,64}$/u.test(rawDiagnosticId) ? rawDiagnosticId : null
  const [targetHostRaw, targetPortRaw] = String(req.url || '').split(':')
  const targetHost = String(targetHostRaw || '').toLowerCase().replace(/\.$/u, '')
  const targetPort = Number(targetPortRaw) || 443
  const isDiagnosticTarget = targetPort === 443 && [
    'daily-cloudcode-pa.googleapis.com',
    'daily-cloudcode-pa.sandbox.googleapis.com',
    'cloudcode-pa.googleapis.com',
  ].includes(targetHost)
  const diagnosticAttempt = Boolean(diagnosticId) || isDiagnosticTarget
  if (diagnosticAttempt) {
    lastDiagnosticConnect = {
      target: `${targetHost}:${targetPort}`,
      diagnosticHeaderReceived: Boolean(diagnosticId),
      stage: 'connect-received',
      routeId: null,
      routeKind: null,
      at: new Date().toISOString(),
    }
  }
  try {
    const upstreamSocket = await establishFailoverTunnel(req.url, diagnosticId)
    let routeInfo = (diagnosticId && diagnosticRoutes.get(diagnosticId)) || upstreamSocket.__antigravityRouteInfo || null
    if (diagnosticId && !routeInfo) {
      if (lastDiagnosticConnect) lastDiagnosticConnect = { ...lastDiagnosticConnect, stage: 'route-identity-missing', at: new Date().toISOString() }
      throw new Error('Diagnostic CONNECT route identity could not be confirmed')
    }
    // Ensure the API result can be bound to this exact tunnel, even if a prior
    // map write was missed. The route metadata is attached to the actual socket.
    if (diagnosticId && routeInfo) diagnosticRoutes.set(diagnosticId, { ...routeInfo })

    if (diagnosticAttempt) {
      lastDiagnosticConnect = {
        target: `${targetHost}:${targetPort}`,
        diagnosticHeaderReceived: Boolean(diagnosticId),
        stage: diagnosticId && routeInfo ? 'route-identified' : 'connect-established-without-diagnostic-id',
        routeId: routeInfo?.id || null,
        routeKind: routeInfo?.kind || null,
        at: new Date().toISOString(),
      }
    }

    const responseHeaders = []
    if (diagnosticId && routeInfo) {
      responseHeaders.push(`X-Antigravity-Diagnostic-Id: ${diagnosticId}`)
      responseHeaders.push(`X-Antigravity-Route-Id: ${routeInfo.id}`)
      responseHeaders.push(`X-Antigravity-Route-Kind: ${routeInfo.kind}`)
      responseHeaders.push(`X-Antigravity-Routing-Effect: ${routeInfo.routingEffect}`)
      responseHeaders.push(`X-Antigravity-Route-Label: ${encodeURIComponent(routeInfo.label || routeInfo.id)}`)
    }
    clientSocket.setKeepAlive(true, 15000)
    clientSocket.write(`HTTP/1.1 200 Connection Established\r\n${responseHeaders.length ? responseHeaders.join('\r\n') + '\r\n' : ''}\r\n`)
    if (head && head.length > 0) {
      upstreamSocket.write(head)
    }
    upstreamSocket.pipe(clientSocket)
    clientSocket.pipe(upstreamSocket)
    upstreamSocket.on('error', () => clientSocket.destroy())
    clientSocket.on('close', () => upstreamSocket.destroy())
  } catch (err) {
    if (diagnosticAttempt && lastDiagnosticConnect) {
      lastDiagnosticConnect = {
        ...lastDiagnosticConnect,
        stage: lastDiagnosticConnect.stage === 'route-identity-missing' ? 'route-identity-missing' : 'connect-failed',
        error: String(err?.message || err).slice(0, 140),
        at: new Date().toISOString(),
      }
    }
    try {
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n')
    } catch {}
    clientSocket.destroy()
  }
})

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    process.exit(0)
  }
})

server.listen(LISTEN_PORT, LISTEN_HOST)

// Compatibility bridge on 127.0.0.1:53129 -> 127.0.0.1:53130 so callers using the configured proxy port reach the active CONNECT bridge.
const compatServer = net.createServer((clientSock) => {
  const upstream = net.connect({ host: LISTEN_HOST, port: LISTEN_PORT })
  clientSock.pipe(upstream)
  upstream.pipe(clientSock)
  clientSock.on('error', () => upstream.destroy())
  upstream.on('error', () => clientSock.destroy())
})
compatServer.on('error', () => {})
if (process.env.ANTIGRAVITY_BRIDGE_DISABLE_COMPAT !== '1') {
  compatServer.listen(LEGACY_AG_DNS_PORT, LISTEN_HOST)
}
