import net from 'node:net'

/**
 * Opens a raw TCP tunnel through a local SOCKS5 proxy using no-auth mode.
 * The destination host is sent as a domain name so Karing handles remote DNS.
 * No TLS interception or certificate bypass is performed here.
 */
export function connectViaSocks5Proxy(proxyHost, proxyPort, targetHost, targetPort, timeoutMs = 4000) {
  const hostBytes = Buffer.from(String(targetHost || ''), 'utf8')
  const port = Number(targetPort)
  if (!hostBytes.length || hostBytes.length > 255) return Promise.reject(new Error('Invalid SOCKS5 target host'))
  if (!Number.isInteger(port) || port < 1 || port > 65535) return Promise.reject(new Error('Invalid SOCKS5 target port'))
  if (!proxyHost || !Number.isInteger(Number(proxyPort)) || Number(proxyPort) < 1 || Number(proxyPort) > 65535) {
    return Promise.reject(new Error('Invalid local SOCKS5 proxy endpoint'))
  }

  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: proxyHost, port: Number(proxyPort) })
    let settled = false
    let stage = 'greeting'
    let buffer = Buffer.alloc(0)
    const timer = setTimeout(() => fail(new Error(`SOCKS5 proxy timeout at ${proxyHost}:${proxyPort}`)), timeoutMs)

    function cleanup() {
      clearTimeout(timer)
      socket.removeListener('data', onData)
      socket.removeListener('error', onError)
      socket.removeListener('close', onClose)
      socket.removeListener('connect', onConnect)
    }

    function fail(error) {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      reject(error instanceof Error ? error : new Error(String(error)))
    }

    function onError(error) { fail(new Error(`SOCKS5 proxy ${proxyHost}:${proxyPort}: ${error.message}`)) }
    function onClose() { if (!settled) fail(new Error(`SOCKS5 proxy closed during ${stage}`)) }

    function onConnect() {
      socket.write(Buffer.from([0x05, 0x01, 0x00]))
    }

    function onData(chunk) {
      if (settled) return
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk
      while (!settled) {
        if (stage === 'greeting') {
          if (buffer.length < 2) return
          const version = buffer[0]
          const method = buffer[1]
          buffer = buffer.subarray(2)
          if (version !== 0x05) return fail(new Error('Karing listener is not speaking SOCKS5'))
          if (method !== 0x00) return fail(new Error('SOCKS5 proxy requires unsupported authentication'))
          stage = 'connect-reply'
          const request = Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, hostBytes.length]),
            hostBytes,
            Buffer.from([(port >> 8) & 0xff, port & 0xff]),
          ])
          socket.write(request)
          continue
        }

        if (stage === 'connect-reply') {
          if (buffer.length < 4) return
          if (buffer[0] !== 0x05) return fail(new Error('Invalid SOCKS5 CONNECT reply version'))
          const replyCode = buffer[1]
          const atyp = buffer[3]
          let replyLength
          if (atyp === 0x01) replyLength = 10
          else if (atyp === 0x04) replyLength = 22
          else if (atyp === 0x03) {
            if (buffer.length < 5) return
            replyLength = 7 + buffer[4]
          } else return fail(new Error('Invalid SOCKS5 reply address type'))
          if (buffer.length < replyLength) return
          if (replyCode !== 0x00) return fail(new Error(`SOCKS5 CONNECT rejected with code ${replyCode}`))

          const extra = buffer.subarray(replyLength)
          settled = true
          cleanup()
          socket.setKeepAlive(true, 15000)
          if (extra.length) {
            socket.pause()
            socket.unshift(extra)
            socket.resume()
          }
          resolve(socket)
          return
        }
      }
    }

    socket.on('data', onData)
    socket.on('error', onError)
    socket.on('close', onClose)
    socket.once('connect', onConnect)
  })
}
