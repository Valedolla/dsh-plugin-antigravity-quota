import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { connectViaSocks5Proxy } from '../bin/socks5-proxy.mjs'

function reserveServer(handler) {
  const server = net.createServer(handler)
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(server))
  })
}

test('SOCKS5 helper negotiates no-auth and sends the target hostname in CONNECT', async (t) => {
  let connectedTarget = null
  let gotProbeResolve
  const gotProbe = new Promise((resolve) => { gotProbeResolve = resolve })
  const server = await reserveServer((client) => {
    let buffer = Buffer.alloc(0)
    let stage = 'greeting'
    client.on('data', (chunk) => {
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk
      if (stage === 'greeting' && buffer.length >= 3) {
        assert.deepEqual([...buffer.subarray(0, 3)], [0x05, 0x01, 0x00])
        buffer = buffer.subarray(3)
        stage = 'connect'
        client.write(Buffer.from([0x05, 0x00]))
      }
      if (stage === 'connect' && buffer.length >= 5) {
        const domainLength = buffer[4]
        const requestLength = 7 + domainLength
        if (buffer.length < requestLength) return
        assert.equal(buffer[0], 0x05)
        assert.equal(buffer[1], 0x01)
        assert.equal(buffer[3], 0x03)
        connectedTarget = {
          host: buffer.subarray(5, 5 + domainLength).toString('utf8'),
          port: buffer.readUInt16BE(5 + domainLength),
        }
        buffer = buffer.subarray(requestLength)
        stage = 'stream'
        client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34]))
        if (buffer.length) {
          gotProbeResolve(buffer.toString('utf8'))
          buffer = Buffer.alloc(0)
        }
      } else if (stage === 'stream' && buffer.length) {
        gotProbeResolve(buffer.toString('utf8'))
        buffer = Buffer.alloc(0)
      }
    })
  })
  const address = server.address()
  const socket = await connectViaSocks5Proxy('127.0.0.1', address.port, 'daily-cloudcode-pa.googleapis.com', 443, 1500)
  t.after(() => {
    socket.destroy()
    return new Promise((resolve) => server.close(() => resolve()))
  })
  assert.deepEqual(connectedTarget, { host: 'daily-cloudcode-pa.googleapis.com', port: 443 })
  socket.write('probe')
  assert.equal(await Promise.race([gotProbe, new Promise((_, reject) => setTimeout(() => reject(new Error('probe timeout')), 1000))]), 'probe')
})

test('SOCKS5 helper rejects proxies that require unsupported authentication', async (t) => {
  const server = await reserveServer((client) => {
    client.once('data', () => client.write(Buffer.from([0x05, 0xff])))
  })
  t.after(() => new Promise((resolve) => server.close(() => resolve())))
  const address = server.address()
  await assert.rejects(
    connectViaSocks5Proxy('127.0.0.1', address.port, 'example.com', 443, 1000),
    /unsupported authentication/
  )
})
