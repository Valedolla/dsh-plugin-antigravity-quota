import net from 'node:net'
import fs from 'node:fs'
import path from 'node:path'

/**
 * Checks if a port is available on 127.0.0.1.
 * Safely handles both EADDRINUSE and Windows EACCES (reserved by WinNAT / Hyper-V).
 */
export function probePort(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const srv = net.createServer()
    srv.unref()
    srv.once('error', () => resolve(false))
    srv.listen({ port, host, exclusive: true }, () => {
      const boundPort = srv.address().port
      srv.close(() => resolve(boundPort))
    })
  })
}

/**
 * Finds the first available port from the preferred list, or requests an ephemeral port from the OS (port 0).
 */
export async function allocatePort(preferredPorts = [53130, 28318, 28319, 28320]) {
  for (const port of preferredPorts) {
    const ok = await probePort(port)
    if (ok) return ok
  }
  const ephemeral = await probePort(0)
  if (!ephemeral) throw new Error('CRITICAL: Failed to allocate any local loopback TCP port')
  return ephemeral
}

/**
 * Strips global proxy environment variables to prevent local child processes
 * from routing loopback traffic through system proxies or TUN devices.
 */
export function getCleanChildEnv(extraEnv = {}) {
  const clean = { ...process.env, ...extraEnv }
  for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy']) {
    delete clean[key]
  }
  clean.NO_PROXY = '127.0.0.1,localhost'
  return clean
}

/**
 * Atomically generates runtime-config.yaml in %LOCALAPPDATA%\AGUnlocker
 * and synchronizes proxy_url across all ~/.cli-proxy-api/antigravity-*.json files.
 */
export function syncRuntimeConfig({ cliPort, bridgePort, authDir, runtimeConfigPath, apiKey = 'antigravity-local-key' }) {
  const proxyUrl = `http://127.0.0.1:${bridgePort}`
  let changed = false

  // 1. Sync all active auth files
  try {
    if (fs.existsSync(authDir)) {
      const files = fs.readdirSync(authDir).filter(f => f.startsWith('antigravity-') && f.endsWith('.json'))
      for (const file of files) {
        const fullPath = path.join(authDir, file)
        try {
          const raw = fs.readFileSync(fullPath, 'utf8').replace(/^\uFEFF/u, '')
          const data = JSON.parse(raw)
          if (data.proxy_url !== proxyUrl) {
            data.proxy_url = proxyUrl
            fs.writeFileSync(fullPath, JSON.stringify(data, null, 2), 'utf8')
            changed = true
          }
        } catch {}
      }
    }
  } catch {}

  // 2. Atomically write runtime-config.yaml
  const yamlContent = [
    `host: "127.0.0.1"`,
    `port: ${cliPort}`,
    `proxy-url: "${proxyUrl}"`,
    `auth-dir: "${authDir.replace(/\\/g, '/')}"`,
    `api-keys:`,
    `  - "${apiKey}"`,
    `debug: false`,
    `logging-to-file: false`,
    '',
  ].join('\n')

  try {
    fs.mkdirSync(path.dirname(runtimeConfigPath), { recursive: true })
    const tmpYaml = `${runtimeConfigPath}.tmp-${process.pid}`
    fs.writeFileSync(tmpYaml, yamlContent, 'utf8')
    fs.renameSync(tmpYaml, runtimeConfigPath)
  } catch {
    // Fallback: direct write if atomic rename is blocked by filesystem locking
    fs.writeFileSync(runtimeConfigPath, yamlContent, 'utf8')
  }

  return { ok: true, changed, proxyUrl }
}
