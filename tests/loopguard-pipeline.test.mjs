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
  for (let i = 0; i < 12; i++) {
    const res = detectRoutingLoop(target, dummySocket)
    if (res.loop) {
      triggered = true
      break
    }
  }
  assert.equal(triggered, true, 'Cascade burst must trigger LoopGuard circuit breaker')
})

test('bindConnectTunnel: closes both sockets when one terminates or errors', async () => {
  const server = net.createServer((sock) => {
    sock.on('error', () => {})
  })
  await new Promise(r => server.listen(0, '127.0.0.1', r))
  const port = server.address().port

  const client = net.connect(port, '127.0.0.1')
  const upstream = net.connect(port, '127.0.0.1')
  await Promise.all([
    new Promise(r => client.once('connect', r)),
    new Promise(r => upstream.once('connect', r)),
  ])

  bindConnectTunnel(client, upstream)
  assert.equal(client.destroyed, false)
  assert.equal(upstream.destroyed, false)

  // Destroy client socket -> upstream socket must be automatically destroyed
  client.destroy()
  await new Promise(r => setTimeout(r, 60))
  assert.equal(upstream.destroyed, true)

  server.close()
})
