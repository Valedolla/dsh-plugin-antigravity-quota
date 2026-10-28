import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'
import { spawn } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-antigravity-route-test-'))
const preferencePath = path.join(tempDir, 'cloudcode-route.json')
const healthPath = path.join(tempDir, 'cloudcode-route-health.json')
process.env.ANTIGRAVITY_ROUTE_PREFERENCE_PATH = preferencePath
process.env.ANTIGRAVITY_ROUTE_HEALTH_PATH = healthPath
const policyPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../bin/cloudcode-route-policy.mjs')
const policy = await import(`${pathToFileURL(policyPath).href}?test=${Date.now()}`)

after(() => fs.rmSync(tempDir, { recursive: true, force: true }))


test('GeoHide EU Smart DNS is first in Auto and uses administrator-provided DoH bootstrap IPs', () => {
  const route = policy.CLOUD_CODE_ROUTES.find((candidate) => candidate.id === 'geohide-eu-doh')
  assert.ok(route)
  assert.equal(route.kind, 'smart-resolver')
  assert.equal(route.url, 'https://eu.geohide.ru/dns-query')
  assert.deepEqual(route.bootstrapIps, ['5.175.161.3', '5.175.161.40', '37.221.93.141', '37.221.93.128', '45.13.237.213', '31.25.239.132', '143.20.64.192'])
  assert.equal(route.region, 'EU')
  assert.equal(route.hostnameFirst, true)
  assert.equal(route.parallelBootstrap, true)
  assert.equal(policy.buildCloudCodeRoutePlan('auto', false)[0].id, 'geohide-eu-doh')
})

test('GeoHide US Smart DNS remains configured as secondary smart resolver', () => {
  const route = policy.CLOUD_CODE_ROUTES.find((candidate) => candidate.id === 'geohide-us-doh')
  assert.ok(route)
  assert.equal(route.kind, 'smart-resolver')
  assert.equal(route.url, 'https://us.geohide.ru/dns-query')
  assert.deepEqual(route.bootstrapIps, ['192.255.159.240', '192.255.159.241', '107.175.76.134', '192.3.233.253'])
  assert.equal(policy.buildCloudCodeRoutePlan('auto', false)[1].id, 'geohide-us-doh')
})

test('manual route plans contain only the selected route', () => {
  assert.deepEqual(policy.buildCloudCodeRoutePlan('doh-comss', true).map((route) => route.id), ['doh-comss'])
  assert.deepEqual(policy.buildCloudCodeRoutePlan('geohide-us-doh', true).map((route) => route.id), ['geohide-us-doh'])
  assert.deepEqual(policy.buildCloudCodeRoutePlan('geohide-eu-doh', true).map((route) => route.id), ['geohide-eu-doh'])
  assert.deepEqual(policy.buildCloudCodeRoutePlan('karing-proxy', true).map((route) => route.id), ['karing-proxy'])
  assert.deepEqual(policy.buildCloudCodeRoutePlan('doh-wlrus', true).map((route) => route.id), ['doh-wlrus'])
})

test('Auto falls back in the declared order and excludes unsafe ag_dns', () => {
  const unsafe = policy.buildCloudCodeRoutePlan('auto', false).map((route) => route.id)
  const safe = policy.buildCloudCodeRoutePlan('auto', true).map((route) => route.id)
  const expected = ['geohide-eu-doh', 'geohide-us-doh', 'doh-comss', 'doh-wlrus']
  assert.deepEqual(unsafe, expected)
  assert.deepEqual(safe, expected)
  assert.ok(!unsafe.some((id) => ['geohide-88', 'geohide-68', 'geohide-67'].includes(id)))
  assert.ok(!unsafe.some((id) => id.startsWith('xbox-')))
  assert.ok(!unsafe.includes('karing-proxy'))
  assert.ok(!unsafe.includes('ag-dns'))
})

test('unsafe manual ag_dns is rejected instead of silently falling back', () => {
  assert.throws(() => policy.buildCloudCodeRoutePlan('ag-dns', false), /disabled/)
})

test('a confirmed generation region rejection removes a route only from Auto', () => {
  policy.recordCloudCodeRouteGenerationResult('doh-comss', {
    ok: false,
    shortStatus: 'HTTP 400',
    status: 'Google returned HTTP 400 FAILED_PRECONDITION',
  })
  assert.ok(!policy.readCloudCodeRouteHealth().locationRejected['doh-comss'])
  // This is the sanitized payload actually stored/reported by the bridge. The
  // classifier label is emitted only after the generation response matches location text.
  policy.recordCloudCodeRouteGenerationResult('doh-comss', {
    ok: false,
    shortStatus: '400 location',
    status: 'Google rejected the Gemini request with a location/eligibility error',
  })
  assert.ok(policy.readCloudCodeRouteHealth().locationRejected['doh-comss'])
  assert.ok(!policy.buildCloudCodeRoutePlan('auto', false).some((route) => route.id === 'doh-comss'))
  assert.deepEqual(policy.buildCloudCodeRoutePlan('doh-comss', false).map((route) => route.id), ['doh-comss'])
  policy.recordCloudCodeRouteGenerationResult('doh-comss', { ok: true, shortStatus: 'Gemini OK', status: 'Cloud Code 200 OK' })
  assert.ok(!policy.readCloudCodeRouteHealth().locationRejected['doh-comss'])
})

test('a real TLS generation failure temporarily excludes its route from Auto but not manual selection', () => {
  policy.recordCloudCodeRouteGenerationResult('doh-wlrus', {
    ok: false,
    shortStatus: 'TLS/error',
    status: 'TLS/connection error during Gemini request',
  })
  assert.equal(policy.readCloudCodeRouteHealth().routeFailures['doh-wlrus'].reason, 'tls-failed')
  assert.ok(!policy.buildCloudCodeRoutePlan('auto', false).some((route) => route.id === 'doh-wlrus'))
  assert.deepEqual(policy.buildCloudCodeRoutePlan('doh-wlrus', false).map((route) => route.id), ['doh-wlrus'])
  assert.match(policy.getCloudCodeRouteOptions().find((option) => option.id === 'doh-wlrus').label, /исключён из Auto на 6 ч/)
  policy.recordCloudCodeRouteGenerationResult('doh-wlrus', {
    ok: true,
    shortStatus: 'Gemini generation OK',
    status: 'HTTP 200: real Gemini generation succeeded',
  })
  assert.ok(!policy.readCloudCodeRouteHealth().routeFailures['doh-wlrus'])
})

test('route health reader tolerates a Windows UTF-8 BOM', () => {
  fs.writeFileSync(healthPath, Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]),
    Buffer.from(JSON.stringify({ locationRejected: {}, routeFailures: {} }), 'utf8'),
  ]))
  assert.deepEqual(policy.readCloudCodeRouteHealth(), { locationRejected: {}, routeFailures: {} })
})

test('temporary TLS failures expire after the cooldown', () => {
  const health = policy.readCloudCodeRouteHealth()
  fs.writeFileSync(healthPath, JSON.stringify({
    locationRejected: health.locationRejected,
    routeFailures: { 'doh-wlrus': { reason: 'tls-failed', at: new Date(Date.now() - 7 * 60 * 60 * 1000).toISOString() } },
  }))
  assert.ok(!policy.readCloudCodeRouteHealth().routeFailures['doh-comss'])
  assert.ok(policy.buildCloudCodeRoutePlan('auto', false).some((route) => route.id === 'doh-comss'))
})

test('route preference round-trips and the UI exposes resolvers distinctly', () => {
  assert.equal(policy.readCloudCodeRoutePreference(), 'auto')
  assert.equal(policy.writeCloudCodeRoutePreference('doh-wlrus').route, 'doh-wlrus')
  assert.equal(policy.readCloudCodeRoutePreference(), 'doh-wlrus')
  const options = policy.getCloudCodeRouteOptions()
  assert.ok(options.some((option) => option.id === 'geohide-eu-doh'))
  assert.match(options.find((option) => option.id === 'karing-proxy').label, /SOCKS5 127\.0\.0\.1:3066/) 
  assert.match(options.find((option) => option.id === 'doh-comss').label, /не egress-прокси/)
  assert.match(options.find((option) => option.id === 'geohide-us-doh').label, /проксирующий DoH/)
  assert.equal(policy.CLOUD_CODE_ROUTES.find((route) => route.id === 'geohide-us-doh').url, 'https://us.geohide.ru/dns-query')
  assert.match(options.find((option) => option.id === 'geohide-eu-doh').label, /проксирующий DoH, регион EU/)
  assert.equal(policy.CLOUD_CODE_ROUTES.find((route) => route.id === 'geohide-eu-doh').url, 'https://eu.geohide.ru/dns-query')
  assert.deepEqual(policy.CLOUD_CODE_ROUTES.find((route) => route.id === 'geohide-us-doh').bootstrapIps, ['192.255.159.240', '192.255.159.241', '107.175.76.134', '192.3.233.253'])
  assert.throws(() => policy.writeCloudCodeRoutePreference('not-a-route'), /Unknown/)
})

function request(port, method, requestPath, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: requestPath, method, headers: body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {} }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => resolve({ statusCode: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.on('error', reject)
    req.end(body || undefined)
  })
}

function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close((error) => error ? reject(error) : resolve(port))
    })
  })
}

test('bridge status starts without a fabricated successful route', async (context) => {
  const port = await reservePort()
  const child = spawn(process.execPath, [path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../bin/xbox-failover-bridge.mjs')], {
    env: { ...process.env, ANTIGRAVITY_BRIDGE_PORT: String(port), ANTIGRAVITY_BRIDGE_DISABLE_COMPAT: '1' },
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  })
  let stderr = ''
  child.stderr.on('data', (chunk) => { stderr += chunk })
  context.after(() => { if (!child.killed) child.kill() })

  let status
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      const response = await request(port, 'GET', '/status')
      if (response.statusCode === 200) {
        status = JSON.parse(response.body)
        break
      }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  assert.ok(status, stderr)
  assert.equal(status.activeRoute, null)
  assert.equal(status.lastApiResult, null)
  assert.deepEqual(status.autoRouteIds, ['geohide-eu-doh', 'geohide-us-doh', 'doh-comss', 'doh-wlrus'])
  assert.equal(status.bridgeBuildId, 'dsh-antigravity-unified-connect-v7')
  const report = await request(port, 'POST', '/route-result', JSON.stringify({ routeId: 'doh-comss', ok: true }))
  assert.equal(report.statusCode, 400)
})


test('legacy compatibility port forwards status to the single primary bridge', async (context) => {
  const mainPort = await reservePort()
  let compatPort = await reservePort()
  while (compatPort === mainPort) compatPort = await reservePort()
  const child = spawn(process.execPath, [path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../bin/xbox-failover-bridge.mjs')], {
    env: {
      ...process.env,
      ANTIGRAVITY_BRIDGE_PORT: String(mainPort),
      ANTIGRAVITY_BRIDGE_COMPAT_PORT: String(compatPort),
      ANTIGRAVITY_BRIDGE_DISABLE_COMPAT: '0',
    },
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  })
  let stderr = ''
  child.stderr.on('data', (chunk) => { stderr += chunk })
  context.after(() => { if (!child.killed) child.kill() })

  let primaryStatus
  for (let attempt = 0; attempt < 30; attempt++) {
    try {
      const response = await request(mainPort, 'GET', '/status')
      if (response.statusCode === 200) {
        primaryStatus = JSON.parse(response.body)
        break
      }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  assert.ok(primaryStatus, stderr)
  const compatResponse = await request(compatPort, 'GET', '/status')
  assert.equal(compatResponse.statusCode, 200)
  const compatStatus = JSON.parse(compatResponse.body)
  assert.equal(compatStatus.bridgeBuildId, 'dsh-antigravity-unified-connect-v7')
  assert.equal(compatStatus.port, mainPort)
  assert.equal(compatStatus.activeRoute, primaryStatus.activeRoute)
})
