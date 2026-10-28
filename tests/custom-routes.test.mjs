import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-custom-routes-test-'))
const customRoutesPath = path.join(tempDir, 'custom-routes.json')
const preferencePath = path.join(tempDir, 'cloudcode-route.json')
const healthPath = path.join(tempDir, 'cloudcode-route-health.json')

process.env.ANTIGRAVITY_CUSTOM_ROUTES_PATH = customRoutesPath
process.env.ANTIGRAVITY_ROUTE_PREFERENCE_PATH = preferencePath
process.env.ANTIGRAVITY_ROUTE_HEALTH_PATH = healthPath

const policyPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../bin/cloudcode-route-policy.mjs')
const policy = await import(`${pathToFileURL(policyPath).href}?test=${Date.now()}`)

after(() => {
  fs.rmSync(tempDir, { recursive: true, force: true })
})

test('custom routes: starts empty when file does not exist', () => {
  assert.deepEqual(policy.readCustomRoutes(), [])
})

test('custom routes: validates required fields and types', () => {
  // Empty or invalid payload
  assert.throws(() => policy.addCustomRoute(null), /Invalid route entry/)
  assert.throws(() => policy.addCustomRoute({}), /Название маршрута обязательно/)
  assert.throws(() => policy.addCustomRoute({ name: 'Test', kind: 'invalid-kind' }), /Недопустимый тип маршрута/)

  // DoH validations
  assert.throws(() => policy.addCustomRoute({ name: 'Test', kind: 'resolver', url: 'http://insecure.com' }), /HTTPS/)
  assert.throws(() => policy.addCustomRoute({ name: 'Test', kind: 'resolver', url: 'not-a-url' }), /URL/)

  // SOCKS5 validations
  assert.throws(() => policy.addCustomRoute({ name: 'Test', kind: 'proxy', host: '127.0.0.1', port: 0 }), /порт/)
  assert.throws(() => policy.addCustomRoute({ name: 'Test', kind: 'proxy', host: '127.0.0.1', port: 70000 }), /порт/)
  assert.throws(() => policy.addCustomRoute({ name: 'Test', kind: 'proxy', host: '127.0.0.1', port: 'invalid' }), /порт/)
})

test('custom routes: prevents collision with built-in route IDs', () => {
  assert.throws(() => policy.addCustomRoute({ id: 'geohide-eu-doh', name: 'Fake EU', kind: 'resolver', url: 'https://fake.com/dns' }), /совпадает со встроенным/)
  assert.throws(() => policy.addCustomRoute({ id: 'karing-proxy', name: 'Fake Karing', kind: 'proxy', host: '127.0.0.1', port: 1080 }), /совпадает со встроенным/)
})

test('custom routes: successfully adds DoH resolver and normalizes URL', () => {
  const added = policy.addCustomRoute({
    name: 'AdGuard Family',
    kind: 'resolver',
    url: 'dns.adguard.com/dns-query',
  })
  assert.ok(added.id.startsWith('custom-'))
  assert.equal(added.name, 'AdGuard Family')
  assert.equal(added.kind, 'resolver')
  assert.equal(added.url, 'https://dns.adguard.com/dns-query')
  assert.equal(added.custom, true)

  const list = policy.readCustomRoutes()
  assert.equal(list.length, 1)
  assert.equal(list[0].id, added.id)
})

test('custom routes: successfully adds Smart DNS with bootstrap IPs', () => {
  const added = policy.addCustomRoute({
    name: 'Custom Smart DNS',
    kind: 'smart-resolver',
    url: 'https://smart.example.com/dns-query',
    bootstrapIps: '1.2.3.4, 5.6.7.8, not-an-ip, 9.10.11.12',
    region: 'DE',
  })
  assert.equal(added.kind, 'smart-resolver')
  assert.deepEqual(added.bootstrapIps, ['1.2.3.4', '5.6.7.8', '9.10.11.12'])
  assert.equal(added.region, 'DE')

  const list = policy.readCustomRoutes()
  assert.equal(list.length, 2)
})

test('custom routes: successfully adds SOCKS5 proxy', () => {
  const added = policy.addCustomRoute({
    name: 'Xray SOCKS5 Inbound',
    kind: 'proxy',
    host: '127.0.0.1',
    port: '10808',
  })
  assert.equal(added.kind, 'proxy')
  assert.equal(added.host, '127.0.0.1')
  assert.equal(added.port, 10808)
  assert.equal(added.protocol, 'socks5')

  const list = policy.readCustomRoutes()
  assert.equal(list.length, 3)
})

test('custom routes: integrated into getAllCloudCodeRoutes and getCloudCodeRouteOptions', () => {
  const all = policy.getAllCloudCodeRoutes()
  assert.ok(all.some(r => r.name === 'AdGuard Family' && r.custom === true))
  assert.ok(all.some(r => r.name === 'Custom Smart DNS' && r.custom === true))
  assert.ok(all.some(r => r.name === 'Xray SOCKS5 Inbound' && r.custom === true))

  const options = policy.getCloudCodeRouteOptions()
  const customOpt = options.find(o => o.label.includes('AdGuard Family'))
  assert.ok(customOpt, 'Custom route option must be formatted in options list')
  assert.match(customOpt.label, /\[Свой\]/)
})

test('custom routes: can be selected manually in buildCloudCodeRoutePlan', () => {
  const custom = policy.readCustomRoutes().find(r => r.name === 'Xray SOCKS5 Inbound')
  assert.ok(custom)
  const plan = policy.buildCloudCodeRoutePlan(custom.id, false)
  assert.equal(plan.length, 1)
  assert.equal(plan[0].id, custom.id)
})

test('custom routes: removeCustomRoute deletes custom route and protects built-in', () => {
  assert.throws(() => policy.removeCustomRoute('geohide-eu-doh'), /Нельзя удалять встроенный/)

  const custom = policy.readCustomRoutes().find(r => r.name === 'AdGuard Family')
  assert.ok(custom)

  // Select this route as active preference
  policy.writeCloudCodeRoutePreference(custom.id)
  assert.equal(policy.readCloudCodeRoutePreference(), custom.id)

  // Remove the route
  const res = policy.removeCustomRoute(custom.id)
  assert.equal(res.ok, true)
  assert.equal(res.removed, custom.id)

  // Verify preference resets to auto when active route is removed
  assert.equal(policy.readCloudCodeRoutePreference(), 'auto')
  assert.ok(!policy.readCustomRoutes().some(r => r.id === custom.id))
})
