import assert from 'node:assert/strict'
import { test } from 'node:test'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { probePort, allocatePort, getCleanChildEnv, syncRuntimeConfig } from '../lib/port-coordinator.mjs'

test('probePort & allocatePort: finds loopback port without throwing', async () => {
  const p = await allocatePort([53130, 28318, 0])
  assert.ok(typeof p === 'number' && p > 0 && p < 65536)
})

test('getCleanChildEnv: strips proxy environment variables', () => {
  const dirty = {
    HTTP_PROXY: 'http://evil.com:8080',
    https_proxy: 'http://evil.com:8080',
    ALL_PROXY: 'socks5://127.0.0.1:1080',
    CUSTOM_VAR: '123',
  }
  const clean = getCleanChildEnv(dirty)
  assert.equal(clean.HTTP_PROXY, undefined)
  assert.equal(clean.https_proxy, undefined)
  assert.equal(clean.ALL_PROXY, undefined)
  assert.equal(clean.CUSTOM_VAR, '123')
  assert.equal(clean.NO_PROXY, '127.0.0.1,localhost')
})

test('syncRuntimeConfig: generates yaml and patches auth file proxy_url', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-port-coord-test-'))
  const authDir = path.join(tempDir, 'auth')
  const runtimeConfigPath = path.join(tempDir, 'runtime-config.yaml')
  fs.mkdirSync(authDir, { recursive: true })

  const fakeAuth = path.join(authDir, 'antigravity-user.json')
  fs.writeFileSync(fakeAuth, JSON.stringify({ email: 'u@test.com', proxy_url: 'http://127.0.0.1:1111' }))

  const res = syncRuntimeConfig({
    cliPort: 8317,
    bridgePort: 53130,
    authDir,
    runtimeConfigPath,
  })

  assert.equal(res.ok, true)
  assert.equal(res.proxyUrl, 'http://127.0.0.1:53130')

  // Verify auth file patched
  const updatedAuth = JSON.parse(fs.readFileSync(fakeAuth, 'utf8'))
  assert.equal(updatedAuth.proxy_url, 'http://127.0.0.1:53130')

  // Verify runtime-config.yaml content
  const yaml = fs.readFileSync(runtimeConfigPath, 'utf8')
  assert.match(yaml, /port: 8317/)
  assert.match(yaml, /proxy-url: "http:\/\/127\.0\.0\.1:53130"/)

  fs.rmSync(tempDir, { recursive: true, force: true })
})
