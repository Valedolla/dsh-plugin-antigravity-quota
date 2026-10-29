import assert from 'node:assert/strict'
import { test } from 'node:test'
import { detectRoutingLoop, bindConnectTunnel } from '../bin/xbox-failover-bridge.mjs'
import net from 'node:net'

test('LoopGuard: detects direct loopback target to 127.0.0.1 or localhost', () => {
  const dummySocket = { remotePort: 12345 }
  const res1 = detectRoutingLoop('127.0.0.1:53130', dummySocket)
  assert.equal(res1.loop, true)
  assert.match(res1.reason, /loopback/i)

  const res2 = detectRoutingLoop('localhost:8317', dummySocket)
  assert.equal(res2.loop, true)

  const res3 = detectRoutingLoop('daily-cloudcode-pa.googleapis.com:443', dummySocket)
  assert.equal(res3.loop, false)
})

test('LoopGuard: detects cascade CONNECT storm on the same host', () => {
  const dummySocket = { remotePort: 23456 }
  const target = 'daily-cloudcode-pa.googleapis.com:443'
  let triggered = false
  // Threshold in bridge is 20 requests per 500ms
  for (let i = 0; i < 25; i++) {
    const res = detectRoutingLoop(target, dummySocket)
    if (res.loop) {
      triggered = true
      break
    }
  }
  assert.equal(triggered, true, 'Cascade burst (>20 reqs/500ms) must trigger LoopGuard circuit breaker')
})

test('bindConnectTunnel: closes both sockets when one terminates or errors', async () => {
  const acceptedSockets = new Set()
  const server = net.createServer((sock) => {
    acceptedSockets.add(sock)
    sock.on('error', () => {})
    sock.once('close', () => acceptedSockets.delete(sock))
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port

  const client = net.connect(port, '127.0.0.1')
  const upstream = net.connect(port, '127.0.0.1')
  await Promise.all([
    new Promise((r) => client.once('connect', r)),
    new Promise((r) => upstream.once('connect', r)),
  ])

  bindConnectTunnel(client, upstream)
  assert.equal(client.destroyed, false)
  assert.equal(upstream.destroyed, false)

  // Destroy client socket -> upstream socket must be automatically destroyed
  client.destroy()
  await new Promise((r) => setTimeout(r, 60))
  assert.equal(upstream.destroyed, true)

  for (const s of acceptedSockets) {
    try { s.destroy() } catch {}
  }
  await new Promise((r) => server.close(r))
})
