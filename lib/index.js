import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import tls from 'node:tls'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { createHash, randomBytes } from 'node:crypto'
import { spawn, execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { CLOUD_CODE_ROUTES, DOH_RESOLVERS, getCloudCodeRouteOptions, readCloudCodeRoutePreference, writeCloudCodeRoutePreference } from '../bin/cloudcode-route-policy.mjs'
import { connectViaSocks5Proxy } from '../bin/socks5-proxy.mjs'

export const name = 'dsh-plugin-antigravity-quota'

if (!process.env.ANTIGRAVITY_API_KEY) {
  process.env.ANTIGRAVITY_API_KEY = 'antigravity-local-key'
}

const PLUGIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const BIN_DIR = path.join(PLUGIN_ROOT, 'bin')
const CPA_DIR = path.join(os.homedir(), '.cli-proxy-api')
const VAULT_DIR = path.join(os.homedir(), '.dsh', 'antigravity-vault')
const STATE_FILE = path.join(VAULT_DIR, 'active-account.json')
const PROXY_PORT_PATH = path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'proxy_port')
const GATE_JSON_PATH = path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker', 'gate.json')

function isAgDnsSafeToUse() {
  try {
    if (!fs.existsSync(GATE_JSON_PATH)) return false
    const gate = JSON.parse(fs.readFileSync(GATE_JSON_PATH, 'utf8'))
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

function checkTcpPort(port, host = '127.0.0.1', timeoutMs = 500) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port })
    const done = (ok) => {
      socket.removeAllListeners()
      socket.destroy()
      resolve(ok)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => done(true))
    socket.once('timeout', () => done(false))
    socket.once('error', () => done(false))
  })
}

function ensureVaultSynced() {
  fs.mkdirSync(VAULT_DIR, { recursive: true })
  if (!fs.existsSync(CPA_DIR)) return
  const legacyVault = path.join(CPA_DIR, 'accounts-vault')
  if (fs.existsSync(legacyVault)) {
    try {
      fs.rmSync(legacyVault, { recursive: true, force: true })
    } catch {}
  }
  const rootFiles = fs.readdirSync(CPA_DIR).filter(f => f.startsWith('antigravity-') && f.endsWith('.json'))
  for (const f of rootFiles) {
    const src = path.join(CPA_DIR, f)
    const dst = path.join(VAULT_DIR, f)
    try {
      const srcStat = fs.statSync(src)
      const dstExists = fs.existsSync(dst)
      if (!dstExists || srcStat.mtimeMs >= fs.statSync(dst).mtimeMs) {
        fs.copyFileSync(src, dst)
      }
    } catch {}
  }
}

function listAccounts() {
  ensureVaultSynced()
  if (!fs.existsSync(VAULT_DIR)) return []
  const files = fs.readdirSync(VAULT_DIR).filter(f => f.startsWith('antigravity-') && f.endsWith('.json'))
  let activeEmail = null
  try {
    if (fs.existsSync(STATE_FILE)) {
      activeEmail = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')).activeEmail || null
    }
  } catch {}

  const rootFiles = fs.existsSync(CPA_DIR)
    ? fs.readdirSync(CPA_DIR).filter(f => f.startsWith('antigravity-') && f.endsWith('.json'))
    : []
  if (!activeEmail && rootFiles.length > 0) {
    try {
      activeEmail = JSON.parse(fs.readFileSync(path.join(CPA_DIR, rootFiles[0]), 'utf8')).email || null
    } catch {}
  }

  const result = []
  for (const f of files) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(VAULT_DIR, f), 'utf8'))
      const email = data.email || f.replace(/^antigravity-/u, '').replace(/\.json$/u, '')
      result.push({
        email,
        filename: f,
        active: email === activeEmail || (result.length === 0 && !activeEmail),
        expired: data.expired || null,
      })
    } catch {}
  }
  if (result.length > 0 && !result.some(a => a.active)) {
    result[0].active = true
  }
  return result
}

let addingAccountInProgress = false
const ANTIGRAVITY_DEFAULT_CALLBACK_PORT = 51121
let oauthSession = null

function getActiveAuthFile() {
  const accounts = listAccounts()
  const active = accounts.find(a => a.active) || accounts[0]
  if (!active) return null
  const rootTarget = path.join(CPA_DIR, active.filename)
  const vaultSource = path.join(VAULT_DIR, active.filename)
  if (!fs.existsSync(rootTarget) && fs.existsSync(vaultSource)) {
    fs.copyFileSync(vaultSource, rootTarget)
  }
  // Remove other antigravity-*.json from root only when NOT performing OAuth
  if (!addingAccountInProgress) {
    for (const acc of accounts) {
      if (acc.filename !== active.filename) {
        const otherRoot = path.join(CPA_DIR, acc.filename)
        try {
          if (fs.existsSync(otherRoot)) fs.unlinkSync(otherRoot)
        } catch {}
      }
    }
  }
  return rootTarget
}

export async function switchAntigravityAccount(targetEmail) {
  const cleanEmail = String(targetEmail || '').trim().toLowerCase()
  if (!cleanEmail || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(cleanEmail)) {
    throw new Error('Некорректный email аккаунта')
  }
  ensureVaultSynced()
  const accounts = listAccounts()
  const found = accounts.find(a => a.email.toLowerCase() === cleanEmail)
  if (!found) {
    throw new Error(`Аккаунт ${cleanEmail} не найден`)
  }
  fs.writeFileSync(STATE_FILE, JSON.stringify({ activeEmail: found.email, updatedAt: Date.now() }, null, 2), 'utf8')
  getActiveAuthFile()
  cachedData = null
  cachedAt = 0
  await ensureAntigravityServices(true)
  return fetchAntigravityQuota(true, false)
}

export async function removeAntigravityAccount(targetEmail) {
  const cleanEmail = String(targetEmail || '').trim().toLowerCase()
  if (!cleanEmail) {
    throw new Error('Не указан email аккаунта для удаления')
  }

  ensureVaultSynced()
  const accounts = listAccounts()
  const found = accounts.find(a => a.email.toLowerCase() === cleanEmail)
  if (!found) {
    throw new Error(`Аккаунт ${cleanEmail} не найден`)
  }

  // 1. Удаляем файл из хранилища Vault
  const vaultPath = path.join(VAULT_DIR, found.filename)
  try {
    if (fs.existsSync(vaultPath)) fs.unlinkSync(vaultPath)
  } catch (_) {}

  // 2. Удаляем файл из папки cli-proxy-api (если он там есть)
  const rootPath = path.join(CPA_DIR, found.filename)
  try {
    if (fs.existsSync(rootPath)) fs.unlinkSync(rootPath)
  } catch (_) {}

  // 3. Если удалили активный аккаунт, переключаем на оставшийся (если есть)
  const remaining = listAccounts()
  if (found.active) {
    if (remaining.length > 0) {
      const nextActive = remaining[0]
      fs.writeFileSync(
        STATE_FILE,
        JSON.stringify({ activeEmail: nextActive.email, updatedAt: Date.now() }, null, 2),
        'utf8'
      )
      getActiveAuthFile()
      cachedData = null
      cachedAt = 0
      await ensureAntigravityServices(true)
      return fetchAntigravityQuota(true, false)
    } else {
      try {
        if (fs.existsSync(STATE_FILE)) fs.unlinkSync(STATE_FILE)
      } catch (_) {}
      cachedData = null
      cachedAt = 0
      return { ok: true, email: null, accounts: [], groups: [] }
    }
  }

  cachedData = null
  cachedAt = 0
  return fetchAntigravityQuota(true, false)
}

async function findFreeLocalPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    let settled = false

    const fail = err => {
      if (settled) return
      settled = true
      reject(err)
    }

    server.once('error', fail)

    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      const port =
        address && typeof address === 'object'
          ? address.port
          : 0

      if (!port) {
        try {
          server.close()
        } catch {}
        fail(new Error('Не удалось получить свободный TCP-порт'))
        return
      }

      server.close(err => {
        if (err) {
          fail(err)
          return
        }

        if (settled) return
        settled = true
        resolve(port)
      })
    })
  })
}

const ANTIGRAVITY_CLIENT_ID =
  '1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com'
const ANTIGRAVITY_CLIENT_SECRET =
  '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'
const ANTIGRAVITY_SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/cclog',
  'https://www.googleapis.com/auth/experimentsandconfigs',
]
const ANTIGRAVITY_FALLBACK_PROJECT_ID = 'bamboo-precept-lgxtn'

async function waitForFreeLocalPort() {
  return findFreeLocalPort()
}

function openExternalUrl(url) {
  return new Promise((resolve, reject) => {
    let settled = false

    const done = (err = null) => {
      if (settled) return
      settled = true
      if (err) reject(err)
      else resolve()
    }

    const tryWindowsHandler = () => {
      let child
      try {
        child = spawn(
          'rundll32.exe',
          ['url.dll,FileProtocolHandler', url],
          {
            windowsHide: true,
            stdio: 'ignore',
            detached: true,
          }
        )
      } catch (err) {
        tryCmdStart(err)
        return
      }

      let settledLocal = false
      child.once('error', err => {
        if (settledLocal) return
        settledLocal = true
        tryCmdStart(err)
      })

      setTimeout(() => {
        if (settledLocal) return
        settledLocal = true
        done()
      }, 700)
    }

    const tryCmdStart = (firstError = null) => {
      let child
      const command = `start "" "${String(url).replaceAll('"', '\\"')}"`

      try {
        child = spawn(
          'cmd.exe',
          ['/d', '/s', '/c', command],
          {
            windowsHide: true,
            stdio: 'ignore',
          }
        )
      } catch (err) {
        done(firstError || err)
        return
      }

      let fallbackSettled = false
      const fail = err => {
        if (fallbackSettled) return
        fallbackSettled = true
        done(
          err ||
            firstError ||
            new Error('Не удалось запустить браузер')
        )
      }

      child.once('error', fail)
      child.once('close', code => {
        if (fallbackSettled) return
        fallbackSettled = true

        if (code && code !== 0) {
          done(
            firstError ||
              new Error(`Не удалось открыть браузер, код ${code}`)
          )
          return
        }

        done()
      })

      setTimeout(() => {
        if (!fallbackSettled) {
          fallbackSettled = true
          done()
        }
      }, 1000)
    }

    if (process.platform === 'win32') {
      tryWindowsHandler()
    } else {
      tryCmdStart()
    }
  })
}

function getNodeBridgePort() {
  return 53130
}

function httpRequestOverProxy({
  host,
  port = 443,
  method = 'GET',
  path: requestPath = '/',
  headers = {},
  body = '',
  timeoutMs = 15000,
}) {
  return new Promise((resolve, reject) => {
    const proxySocket = net.createConnection({
      host: '127.0.0.1',
      port: getNodeBridgePort(),
    })

    let settled = false
    let connectBuffer = Buffer.alloc(0)
    let tlsSocket = null

    const finish = (err, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)

      try {
        if (tlsSocket) tlsSocket.destroy()
        else proxySocket.destroy()
      } catch {}

      if (err) reject(err)
      else resolve(value)
    }

    const timer = setTimeout(() => {
      finish(new Error(`Proxy timeout for ${host}:${port}`))
    }, timeoutMs)

    proxySocket.once('error', err => {
      finish(err)
    })

    proxySocket.once('connect', () => {
      proxySocket.write(
        `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\nConnection: keep-alive\r\n\r\n`
      )
    })

    proxySocket.on('data', firstChunk => {
      if (tlsSocket) return

      connectBuffer = Buffer.concat([
        connectBuffer,
        firstChunk,
      ])

      const headerEnd = connectBuffer.indexOf(
        Buffer.from('\r\n\r\n')
      )

      if (headerEnd < 0) return

      const headerText = connectBuffer
        .subarray(0, headerEnd)
        .toString('latin1')

      const statusLine =
        headerText.split('\r\n')[0] || ''

      if (!/\s200\s/u.test(statusLine)) {
        finish(
          new Error(
            `Proxy CONNECT failed for ${host}: ${statusLine}`
          )
        )
        return
      }

      const remaining = connectBuffer.subarray(
        headerEnd + 4
      )

      proxySocket.removeAllListeners('data')

      tlsSocket = tls.connect({
        socket: proxySocket,
        servername: host,
        rejectUnauthorized: true,
      })

      tlsSocket.once('error', finish)

      tlsSocket.once('secureConnect', () => {
        const normalizedHeaders = {
          Host: host,
          Accept: '*/*',
          Connection: 'close',
          ...headers,
        }

        const lines = [
          `${method} ${requestPath} HTTP/1.1`,
          ...Object.entries(normalizedHeaders).map(
            ([key, value]) => `${key}: ${value}`
          ),
        ]

        if (body) {
          lines.push(
            `Content-Length: ${Buffer.byteLength(body)}`
          )
        }

        lines.push('', body)
        tlsSocket.write(lines.join('\r\n'))

        if (remaining.length) {
          tlsSocket.unshift(remaining)
        }
      })

      let responseBuffer = Buffer.alloc(0)

      tlsSocket.on('data', chunk => {
        responseBuffer = Buffer.concat([
          responseBuffer,
          chunk,
        ])
      })

      tlsSocket.once('end', () => {
        const headerEndIndex = responseBuffer.indexOf(
          Buffer.from('\r\n\r\n')
        )

        if (headerEndIndex < 0) {
          finish(
            new Error(
              `Invalid HTTPS response from ${host}`
            )
          )
          return
        }

        const headerText = responseBuffer
          .subarray(0, headerEndIndex)
          .toString('latin1')

        const lines = headerText.split('\r\n')
        const statusParts = (lines.shift() || '').split(' ')
        const statusCode = Number(statusParts[1]) || 0
        const responseHeaders = {}

        for (const line of lines) {
          const idx = line.indexOf(':')
          if (idx <= 0) continue
          const key = line.slice(0, idx).trim().toLowerCase()
          const value = line.slice(idx + 1).trim()
          responseHeaders[key] = value
        }

        const rawBody = responseBuffer.subarray(
          headerEndIndex + 4
        )

        finish(null, {
          statusCode,
          headers: responseHeaders,
          body: rawBody.toString('utf8'),
        })
      })
    })
  })
}

async function fetchProjectIdForToken(accessToken) {
  const endpoints = [
    'https://cloudcode-pa.googleapis.com',
    'https://daily-cloudcode-pa.googleapis.com',
    'https://daily-cloudcode-pa.sandbox.googleapis.com',
  ]

  const clientMetadata = {
    ideType: 'IDE_UNSPECIFIED',
    platform: 'PLATFORM_UNSPECIFIED',
    pluginType: 'GEMINI',
  }

  const requestBody = JSON.stringify({
    metadata: clientMetadata,
  })

  const projectHeaders = {
    Authorization: `Bearer ${accessToken}`,
    Accept: '*/*',
    'Content-Type': 'application/json',
    'User-Agent': 'google-api-nodejs-client/9.15.1',
    'X-Goog-Api-Client': 'google-cloud-sdk vscode_cloudshelleditor/0.1',
    'Client-Metadata': JSON.stringify(clientMetadata),
  }

  const errors = []

  for (const baseUrl of endpoints) {
    const parsed = new URL(
      `${baseUrl}/v1internal:loadCodeAssist`
    )

    const hosts = [
      {
        mode: 'direct',
        host: parsed.hostname,
      },
      {
        mode: 'proxy',
        host: parsed.hostname,
      },
    ]

    for (const route of hosts) {
      try {
        let result

        if (route.mode === 'direct') {
          const controller = new AbortController()
          const timeout = setTimeout(
            () => controller.abort(),
            12000
          )

          try {
            const response = await fetch(
              parsed.href,
              {
                method: 'POST',
                headers: projectHeaders,
                body: requestBody,
                signal: controller.signal,
              }
            )

            result = {
              statusCode: response.status,
              body: await response.text(),
            }
          } finally {
            clearTimeout(timeout)
          }
        } else {
          result = await httpRequestOverProxy({
            host: parsed.hostname,
            method: 'POST',
            path: `${parsed.pathname}${parsed.search}`,
            headers: projectHeaders,
            body: requestBody,
            timeoutMs: 15000,
          })
        }

        if (
          result.statusCode >= 200 &&
          result.statusCode < 300
        ) {
          let data
          try {
            data = JSON.parse(result.body)
          } catch {
            data = null
          }

          const projectID = String(
            data?.cloudaicompanionProject ||
              data?.projectId ||
              data?.project ||
              data?.response?.cloudaicompanionProject ||
              ''
          ).trim()

          if (projectID) {
            return {
              projectID,
              source: `${route.mode}:${parsed.hostname}`,
              fallback: false,
            }
          }

          errors.push(
            `${route.mode}:${parsed.hostname}: HTTP ${result.statusCode}, project_id отсутствует`
          )
        } else {
          errors.push(
            `${route.mode}:${parsed.hostname}: HTTP ${result.statusCode}`
          )
        }
      } catch (err) {
        errors.push(
          `${route.mode}:${parsed.hostname}: ${err?.message || err}`
        )
      }
    }
  }

  return {
    projectID: ANTIGRAVITY_FALLBACK_PROJECT_ID,
    source: 'fallback',
    fallback: true,
    errors: errors.slice(-8),
  }
}

async function exchangeAntigravityCode({ code, callbackPort, codeVerifier }) {
  const redirectUri = `http://localhost:${callbackPort}/oauth-callback`
  const tokenController = new AbortController()
  const tokenTimeout = setTimeout(() => tokenController.abort(), 20000)
  let tokenResponse
  try {
    const form = new URLSearchParams({
      code,
      client_id: ANTIGRAVITY_CLIENT_ID,
      client_secret: ANTIGRAVITY_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      code_verifier: codeVerifier,
    })
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form,
      signal: tokenController.signal,
    })
    const text = await response.text()
    if (!response.ok) {
      throw new Error(`Google token exchange HTTP ${response.status}: ${text.slice(0, 1000)}`)
    }
    tokenResponse = JSON.parse(text)
  } finally {
    clearTimeout(tokenTimeout)
  }

  const accessToken = String(tokenResponse.access_token || '').trim()
  const refreshToken = String(tokenResponse.refresh_token || '').trim()
  if (!accessToken || !refreshToken) {
    throw new Error('Google token exchange не вернул access_token/refresh_token')
  }

  const userController = new AbortController()
  const userTimeout = setTimeout(() => userController.abort(), 15000)
  let email
  try {
    const response = await fetch('https://www.googleapis.com/oauth2/v1/userinfo?alt=json', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'User-Agent': 'antigravity',
      },
      signal: userController.signal,
    })
    const text = await response.text()
    if (!response.ok) {
      throw new Error(`Google userinfo HTTP ${response.status}: ${text.slice(0, 1000)}`)
    }
    email = String(JSON.parse(text).email || '').trim().toLowerCase()
  } finally {
    clearTimeout(userTimeout)
  }

  if (!email) {
    throw new Error('Google userinfo не вернул email')
  }

  const project = await fetchProjectIdForToken(accessToken)
  return {
    email,
    accessToken,
    refreshToken,
    expiresIn: Number(tokenResponse.expires_in) || 3600,
    tokenType: String(tokenResponse.token_type || 'Bearer'),
    projectID: project.projectID,
    projectSource: project.source,
    projectFallback: project.fallback,
    projectErrors: project.errors || [],
  }
}

async function performAntigravityOAuth({ onReady = null, onReceived = null, bindCancel = null } = {}) {
  let callbackPort = ANTIGRAVITY_DEFAULT_CALLBACK_PORT
  if (await checkTcpPort(callbackPort, '127.0.0.1', 150)) {
    callbackPort = await waitForFreeLocalPort()
  }

  const state = randomBytes(24).toString('hex')
  const codeVerifier = randomBytes(32).toString('hex')
  const codeChallenge = createHash('sha256')
    .update(codeVerifier)
    .digest('base64url')

  return new Promise(async (resolve, reject) => {
    let server
    let finished = false
    const timeout = setTimeout(() => {
      finish(new Error('Google OAuth не завершился за 5 минут'))
    }, 5 * 60 * 1000)

    const finish = (err, value) => {
      if (finished) return
      finished = true
      clearTimeout(timeout)
      try {
        server?.close()
      } catch {}
      if (err) reject(err)
      else resolve(value)
    }

    if (typeof bindCancel === 'function') {
      try {
        bindCancel(() => {
          finish(new Error('Авторизация отменена пользователем'))
        })
      } catch (_) {}
    }

    server = http.createServer((request, response) => {
      try {
        const requestUrl = new URL(request.url || '/', `http://127.0.0.1:${callbackPort}`)
        if (requestUrl.pathname !== '/oauth-callback') {
          response.writeHead(404)
          response.end('Not found')
          return
        }
        const receivedState = requestUrl.searchParams.get('state') || ''
        const errorValue = requestUrl.searchParams.get('error') || ''
        const code = requestUrl.searchParams.get('code') || ''

        response.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
        })
        if (errorValue) {
          response.end('<h2>Google OAuth failed</h2><p>Вернитесь в Harness и повторите попытку.</p>')
        } else {
          response.end('<h2>Google OAuth successful</h2><p>Авторизация успешно завершена! Это окно можно закрыть.</p>')
        }

        if (receivedState !== state) {
          finish(new Error('Google OAuth state mismatch'))
          return
        }
        if (errorValue) {
          finish(new Error(`Google OAuth error: ${errorValue}`))
          return
        }
        if (!code) {
          finish(new Error('Google OAuth не вернул authorization code'))
          return
        }

        if (typeof onReceived === 'function') {
          try { onReceived() } catch (_) {}
        }

        void (async () => {
          try {
            const oauth = await exchangeAntigravityCode({ code, callbackPort, codeVerifier })
            finish(null, oauth)
          } catch (err) {
            finish(err)
          }
        })()
      } catch (err) {
        finish(err)
      }
    })

    server.on('error', finish)

    try {
      await new Promise((resolveListen, rejectListen) => {
        server.listen(callbackPort, '127.0.0.1', resolveListen)
        server.once('error', rejectListen)
      })

      const params = new URLSearchParams({
        access_type: 'offline',
        client_id: ANTIGRAVITY_CLIENT_ID,
        prompt: 'consent',
        redirect_uri: `http://localhost:${callbackPort}/oauth-callback`,
        response_type: 'code',
        scope: ANTIGRAVITY_SCOPES.join(' '),
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })

      const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + params.toString()
      console.log(`[antigravity-quota] opening native OAuth callback on port ${callbackPort}`)

      if (typeof onReady === 'function') {
        await onReady({ authUrl, state, callbackPort })
      } else {
        await openExternalUrl(authUrl)
      }
    } catch (err) {
      finish(err)
    }
  })
}

async function persistAntigravityOAuth(oauth) {
  const filename = `antigravity-${oauth.email}.json`
  const authData = {
    type: 'antigravity',
    access_token: oauth.accessToken,
    refresh_token: oauth.refreshToken,
    expires_in: oauth.expiresIn,
    token_type: oauth.tokenType,
    timestamp: Date.now(),
    expired: new Date(Date.now() + oauth.expiresIn * 1000).toISOString(),
    email: oauth.email,
    project_id: oauth.projectID,
  }

  fs.mkdirSync(CPA_DIR, { recursive: true })
  fs.mkdirSync(VAULT_DIR, { recursive: true })

  const rootPath = path.join(CPA_DIR, filename)
  const vaultPath = path.join(VAULT_DIR, filename)
  const serialized = JSON.stringify(authData, null, 2) + '\n'

  const tmpRootPath = `${rootPath}.tmp-${process.pid}-${Date.now()}`
  const tmpVaultPath = `${vaultPath}.tmp-${process.pid}-${Date.now()}`

  try {
    fs.writeFileSync(tmpRootPath, serialized, 'utf8')
    fs.renameSync(tmpRootPath, rootPath)
    fs.writeFileSync(tmpVaultPath, serialized, 'utf8')
    fs.renameSync(tmpVaultPath, vaultPath)
  } finally {
    try {
      if (fs.existsSync(tmpRootPath)) fs.unlinkSync(tmpRootPath)
    } catch {}
    try {
      if (fs.existsSync(tmpVaultPath)) fs.unlinkSync(tmpVaultPath)
    } catch {}
  }

  ensureVaultSynced()
  const result = await switchAntigravityAccount(oauth.email)
  return {
    ...result,
    email: oauth.email,
    accounts: listAccounts(),
    oauthWarning: oauth.projectFallback
      ? `Google аккаунт добавлен. Project ID получен через fallback (${oauth.projectID}), потому что loadCodeAssist не ответил корректно.`
      : undefined,
  }
}

function cleanupOAuthSession() {
  if (oauthSession?.cleanupTimer) {
    clearTimeout(oauthSession.cleanupTimer)
  }
  oauthSession = null
}

function startBackgroundAntigravityOAuth() {
  if (oauthSession) {
    throw new Error('Авторизация нового Google аккаунта уже выполняется')
  }

  const session = {
    state: null,
    authUrl: null,
    callbackPort: null,
    status: 'starting',
    error: null,
    result: null,
    completion: null,
    cleanupTimer: null,
    cancel: null,
  }

  oauthSession = session
  addingAccountInProgress = true

  session.completion = (async () => {
    try {
      const oauth = await performAntigravityOAuth({
        bindCancel: fn => {
          session.cancel = fn
        },
        onReady: async info => {
          session.state = info.state
          session.authUrl = info.authUrl
          session.callbackPort = info.callbackPort
          session.status = 'wait'
          try {
            await openExternalUrl(info.authUrl)
          } catch (_) {}
        },
        onReceived: () => {
          session.status = 'received'
        },
      })

      const existing = new Set(
        listAccounts().map(a => String(a.email || '').trim().toLowerCase())
      )

      if (existing.has(oauth.email)) {
        throw new Error(`Google аккаунт ${oauth.email} уже есть в плагине`)
      }

      session.status = 'processing'
      session.result = await persistAntigravityOAuth(oauth)
      session.status = 'ok'
    } catch (err) {
      session.status = 'error'
      session.error = String(err?.message || err)
    } finally {
      addingAccountInProgress = false
      session.cleanupTimer = setTimeout(() => {
        if (oauthSession === session) cleanupOAuthSession()
      }, 5 * 60 * 1000)
    }
  })()

  return session
}

async function waitForOAuthSession(session) {
  await session.completion
  return session
}

export async function startAddAntigravityAccount() {
  const session = startBackgroundAntigravityOAuth()
  await waitForOAuthSession(session)

  if (session.status === 'error') {
    throw new Error(session.error || 'Google OAuth завершился ошибкой')
  }

  return session.result
}

function syncProxyConfigs(upstreamPort) {
  const proxyUrl = `http://127.0.0.1:${upstreamPort}`
  let changed = false
  const cfgPath = path.join(BIN_DIR, 'config.yaml')
  try {
    if (fs.existsSync(cfgPath)) {
      const raw = fs.readFileSync(cfgPath, 'utf8')
      const proxyLine = /^([\t ]*proxy-url[\t ]*:[\t ]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^#\r\n]*)([\t ]*(?:#.*)?)$/mu
      const next = proxyLine.test(raw)
        ? raw.replace(proxyLine, `$1"${proxyUrl}"$2`)
        : `${raw.replace(/\s*$/u, '')}\nproxy-url: "${proxyUrl}"\n`
      if (next !== raw) {
        fs.writeFileSync(cfgPath, next, 'utf8')
        changed = true
      }
    }
  } catch {}
  for (const dir of [CPA_DIR, VAULT_DIR]) {
    if (!fs.existsSync(dir)) continue
    for (const f of fs.readdirSync(dir).filter(x => x.startsWith('antigravity-') && x.endsWith('.json'))) {
      try {
        const authPath = path.join(dir, f)
        const auth = JSON.parse(fs.readFileSync(authPath, 'utf8'))
        if (auth.proxy_url !== proxyUrl) {
          auth.proxy_url = proxyUrl
          fs.writeFileSync(authPath, JSON.stringify(auth, null, 2), 'utf8')
          changed = true
        }
      } catch {}
    }
  }
  return changed
}

function normalizeProxyUrlForDiagnostics(value) {
  if (typeof value !== 'string' || !value.trim()) return null
  try {
    const parsed = new URL(value.trim())
    if (!['http:', 'https:'].includes(parsed.protocol)) return 'unsupported proxy scheme'
    const host = parsed.hostname.includes(':') ? `[${parsed.hostname}]` : parsed.hostname
    const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80')
    // Never expose credentials, path, query parameters, or fragments from a proxy URL.
    return `${parsed.protocol}//${host}:${port}`
  } catch {
    return 'invalid proxy URL'
  }
}

function getWindowsListenerDiagnostics() {
  if (process.platform !== 'win32') return { supported: false, listeners: [] }
  const script = String.raw`
$ports = @(53129, 53130, 8317)
$items = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $ports -contains [int]$_.LocalPort } | ForEach-Object {
  $proc = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $_.OwningProcess) -ErrorAction SilentlyContinue
  $cmd = [string]$proc.CommandLine
  $processStartTime = $null
  if ($proc.CreationDate) { $processStartTime = ([datetime]$proc.CreationDate).ToUniversalTime().ToString('o') }
  [PSCustomObject]@{
    port = [int]$_.LocalPort
    pid = [int]$_.OwningProcess
    processName = [string]$proc.Name
    processStartTime = $processStartTime
    bridgeScript = ($cmd -match '(?i)xbox-failover-bridge\.mjs')
    cliProxyExe = ([string]$proc.Name -ieq 'cli-proxy-api.exe')
  }
})
if ($items.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject @($items) -Compress }
`
  try {
    const output = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true, timeout: 2500,
    }).trim()
    const parsed = output ? JSON.parse(output) : []
    return { supported: true, listeners: Array.isArray(parsed) ? parsed : [parsed] }
  } catch {
    return { supported: false, listeners: [] }
  }
}

function stopStaleBridgeListenerIfOwned() {
  if (process.platform !== 'win32') return false
  const diagnostics = getWindowsListenerDiagnostics()
  const owner = diagnostics.listeners.find((listener) => Number(listener.port) === 53130)
  // Only stop a known bridge script. Never terminate an unrelated process occupying the port.
  if (!owner || owner.bridgeScript !== true || !Number.isInteger(Number(owner.pid)) || Number(owner.pid) <= 4) return false
  try {
    execFileSync('taskkill.exe', ['/F', '/PID', String(owner.pid)], {
      stdio: 'ignore', windowsHide: true, timeout: 3000,
    })
    if (externalBridgeChild && Number(externalBridgeChild.pid) === Number(owner.pid)) {
      externalBridgeChild = null
      lastExternalBridgeSpawnAttempt = 0
    }
    return true
  } catch {
    return false
  }
}

function getProxyRoutingDiagnostics(listeners = getWindowsListenerDiagnostics(), cliRestartVerified = null) {
  const expectedProxyUrl = 'http://127.0.0.1:53130'
  let configYamlProxyUrl = null
  let activeAuthProxyUrl = null
  let configYamlMtimeMs = null
  try {
    configYamlMtimeMs = fs.statSync(path.join(BIN_DIR, 'config.yaml')).mtimeMs
    const raw = fs.readFileSync(path.join(BIN_DIR, 'config.yaml'), 'utf8')
    const match = raw.match(/^\s*proxy-url\s*:\s*(?:"([^"]*)"|'([^']*)'|([^#\s]+))/mu)
    if (match) configYamlProxyUrl = normalizeProxyUrlForDiagnostics(match[1] || match[2] || match[3])
  } catch {}
  try {
    const authPath = getActiveAuthFile()
    if (authPath && fs.existsSync(authPath)) {
      const auth = JSON.parse(fs.readFileSync(authPath, 'utf8'))
      activeAuthProxyUrl = normalizeProxyUrlForDiagnostics(auth.proxy_url)
    }
  } catch {}
  const cli = listeners.listeners.filter((listener) => Number(listener.port) === 8317)
  const validCliListeners = cli.filter((listener) => listener.cliProxyExe === true && Number.isFinite(Date.parse(listener.processStartTime || '')))
  const cliProcessStartedAfterConfig = configYamlMtimeMs !== null && validCliListeners.length
    ? validCliListeners.every((listener) => Date.parse(listener.processStartTime) >= configYamlMtimeMs)
    : null
  const bridge = listeners.listeners.filter((listener) => Number(listener.port) === 53130)
  const compat = listeners.listeners.filter((listener) => Number(listener.port) === 53129)
  return {
    expectedProxyUrl,
    configYamlProxyUrl,
    activeAuthProxyUrl,
    filesMatchExpected: configYamlProxyUrl === expectedProxyUrl && activeAuthProxyUrl === expectedProxyUrl,
    cliRestartVerified,
    cliProcessStartedAfterConfig,
    listenerInspectionSupported: listeners.supported === true,
    listeners: listeners.listeners,
    listenerChecks: {
      bridge53130OwnedByBridge: bridge.some((listener) => listener.bridgeScript === true),
      compat53129SharesBridgePid: bridge.some((main) => main.bridgeScript === true && compat.some((old) => old.pid === main.pid)),
      cliProxy8317OwnedByCliProxyApi: cli.some((listener) => listener.cliProxyExe === true),
    },
  }
}

let cliProxyChild = null
let lastCliProxySpawnAttempt = 0
const CLI_PROXY_COOLDOWN_MS = 15000

function isCliProxyRunningInOs() {
  if (process.platform !== 'win32') return false
  try {
    const out = execFileSync('tasklist.exe', ['/FI', 'IMAGENAME eq cli-proxy-api.exe', '/NH'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
      timeout: 2500,
    })
    return out.toLowerCase().includes('cli-proxy-api.exe')
  } catch {
    return false
  }
}

function startCliProxyHidden() {
  // 1. Singleton guard: if child already alive, do not spawn another
  if (cliProxyChild && !cliProxyChild.killed && cliProxyChild.exitCode === null) {
    return
  }

  // 2. Cooldown guard: never attempt to spawn faster than once every 15s
  const now = Date.now()
  if (now - lastCliProxySpawnAttempt < CLI_PROXY_COOLDOWN_MS) {
    return
  }
  lastCliProxySpawnAttempt = now

  // 3. OS-wide guard: if any cli-proxy-api.exe is already running, skip spawn
  if (isCliProxyRunningInOs()) {
    return
  }

  const exePath = path.join(BIN_DIR, 'cli-proxy-api.exe')
  const cfgPath = path.join(BIN_DIR, 'config.yaml')
  if (!fs.existsSync(exePath) || !fs.existsSync(cfgPath)) return

  try {
    const child = spawn(exePath, ['-config', cfgPath], {
      cwd: BIN_DIR,
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
      env: {
        ...process.env,
        NO_PROXY: '127.0.0.1,localhost,[::1],::1',
        no_proxy: '127.0.0.1,localhost,[::1],::1',
        HTTP_PROXY: '',
        HTTPS_PROXY: '',
        ALL_PROXY: '',
      },
    })
    child.unref()
    cliProxyChild = child
    child.on('exit', () => { cliProxyChild = null })
    child.on('error', () => { cliProxyChild = null })
  } catch {
    cliProxyChild = null
  }
}

let agDnsChild = null
let lastAgDnsSpawnAttempt = 0
const AG_DNS_COOLDOWN_MS = 60000

function isAgDnsRunningInOs() {
  if (process.platform !== 'win32') return false
  try {
    const out = execFileSync('tasklist.exe', ['/FI', 'IMAGENAME eq ag_dns.exe', '/NH'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
      timeout: 2500,
    })
    return out.toLowerCase().includes('ag_dns.exe')
  } catch {
    return false
  }
}

function startAgDnsHidden() {
  // 1. Singleton guard: if this plugin already spawned ag_dns and it is running, never spawn another
  if (agDnsChild && !agDnsChild.killed && agDnsChild.exitCode === null) {
    return
  }

  // 2. Cooldown guard: never attempt to spawn faster than once every 60 seconds
  const now = Date.now()
  if (now - lastAgDnsSpawnAttempt < AG_DNS_COOLDOWN_MS) {
    return
  }
  lastAgDnsSpawnAttempt = now

  // 3. Ensure C:\ProgramData\AGUnlocker exists and has ag_dns.exe
  const programDataDir = 'C:\\ProgramData\\AGUnlocker'
  const programDataExe = path.join(programDataDir, 'ag_dns.exe')
  try {
    if (!fs.existsSync(programDataDir)) {
      fs.mkdirSync(programDataDir, { recursive: true })
    }
    const realExe = path.join(BIN_DIR, 'ag_dns_real.exe')
    const sourceExe = fs.existsSync(realExe) ? realExe : path.join(BIN_DIR, 'ag_dns.exe')
    if (fs.existsSync(sourceExe)) {
      if (!fs.existsSync(programDataExe) || fs.statSync(programDataExe).size < 1000000) {
        fs.copyFileSync(sourceExe, programDataExe)
      }
    }
  } catch {}

  const exePath = fs.existsSync(programDataExe) ? programDataExe : path.join(BIN_DIR, 'ag_dns.exe')
  if (!fs.existsSync(exePath)) return

  // 4. OS-wide guard: if any ag_dns.exe process is already active anywhere in Windows, do NOT spawn
  if (isAgDnsRunningInOs()) {
    return
  }

  try {
    const child = spawn(exePath, ['--dns-forwarder'], {
      cwd: path.dirname(exePath),
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    })
    child.unref()
    agDnsChild = child
    child.on('exit', () => { agDnsChild = null })
    child.on('error', () => { agDnsChild = null })
  } catch {
    agDnsChild = null
  }
}

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

function queryDohWireA(resolver, host, timeoutMs = 2200) {
  return new Promise((resolve, reject) => {
    let query
    let endpoint
    try {
      query = buildDohAQuery(host)
      endpoint = new URL(resolver.url)
      if (endpoint.protocol !== 'https:') throw new Error('DoH endpoint must use HTTPS')
    } catch (err) {
      reject(err)
      return
    }
    const req = https.request({
      hostname: endpoint.hostname,
      port: endpoint.port || 443,
      path: `${endpoint.pathname}${endpoint.search}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/dns-message',
        Accept: 'application/dns-message',
        'Content-Length': query.packet.length,
        'User-Agent': 'dsh-plugin-antigravity-quota/1.4.3',
      },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = []
      let size = 0
      res.on('data', chunk => {
        size += chunk.length
        if (size > 65536) {
          req.destroy(new Error('DoH response exceeded 64 KiB'))
          return
        }
        chunks.push(chunk)
      })
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`${resolver.name} DoH HTTP ${res.statusCode || 0}`))
          return
        }
        try {
          const addresses = parseDohAResponse(Buffer.concat(chunks), query.id)
          if (!addresses.length) throw new Error(`${resolver.name} returned no A records for ${host}`)
          resolve(addresses)
        } catch (err) {
          reject(err)
        }
      })
    })
    req.on('timeout', () => req.destroy(new Error(`${resolver.name} DoH timeout`)))
    req.on('error', reject)
    req.end(query.packet)
  })
}

function queryDohJsonA(resolver, host, timeoutMs = 2200) {
  return new Promise((resolve, reject) => {
    let endpoint
    try {
      endpoint = new URL(resolver.url)
      endpoint.searchParams.set('name', host)
      endpoint.searchParams.set('type', 'A')
      if (endpoint.protocol !== 'https:') throw new Error('DoH endpoint must use HTTPS')
    } catch (err) { reject(err); return }
    const req = https.request({
      hostname: endpoint.hostname,
      port: endpoint.port || 443,
      path: `${endpoint.pathname}${endpoint.search}`,
      method: 'GET',
      headers: { Accept: 'application/dns-json, application/json', 'User-Agent': 'dsh-plugin-antigravity-quota/1.4.3' },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = []
      let size = 0
      res.on('data', chunk => {
        size += chunk.length
        if (size > 65536) { req.destroy(new Error('DoH JSON response exceeded 64 KiB')); return }
        chunks.push(chunk)
      })
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) { reject(new Error(`${resolver.name} DoH JSON HTTP ${res.statusCode || 0}`)); return }
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'))
          if (data.Status && data.Status !== 0) throw new Error(`DNS response code ${data.Status}`)
          const addresses = [...new Set((data.Answer || []).filter(a => Number(a.type) === 1 && typeof a.data === 'string').map(a => a.data).filter(isUsablePublicIPv4))]
          if (!addresses.length) throw new Error(`${resolver.name} returned no A records for ${host}`)
          resolve(addresses)
        } catch (err) { reject(err) }
      })
    })
    req.on('timeout', () => req.destroy(new Error(`${resolver.name} DoH JSON timeout`)))
    req.on('error', reject)
    req.end()
  })
}

async function queryDohA(resolver, host, timeoutMs = 2200) {
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
      if (typeof setRouteLabel === 'function') setRouteLabel(`DoH ${resolver.name} (${address})`)
      socket.__dohResolver = resolver.id
      socket.__dohAddresses = addresses
      return socket
    } catch (err) {
      lastError = err
    }
  }
  throw new Error(`${resolver.name}: DNS [${addresses.join(', ')}], TCP failed: ${lastError?.message || 'no reachable A address'}`)
}

let builtinNodeBridgeServer = null

function connectTcpSocket(host, port, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    let resolved = false
    const sock = net.connect({ host, port })
    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true
        sock.destroy()
        reject(new Error(`Timeout connecting to ${host}:${port}`))
      }
    }, timeoutMs)

    sock.once('connect', () => {
      if (!resolved) {
        resolved = true
        clearTimeout(timer)
        sock.setKeepAlive(true, 15000)
        resolve(sock)
      }
    })

    sock.once('error', (err) => {
      if (!resolved) {
        resolved = true
        clearTimeout(timer)
        sock.destroy()
        reject(err)
      }
    })
  })
}

const XBOX_AUTH = 'Basic YWd5X2ZyZWVfdGlyZTpwYXNzd29yZC1mb3ItbW9tJ3MtSGFDS2VSIzIwMjYh'
const XBOX_RELAYS = CLOUD_CODE_ROUTES.filter((route) => route.kind === 'relay')
const GEOHIDE_SNI_IPS = CLOUD_CODE_ROUTES.filter((route) => route.kind === 'gateway').map((route) => route.host)

let activeBridgeRoute = null

function connectViaXboxRelay(relay, targetHostPort, timeoutMs = 4500, updateActiveRoute = true) {
  return new Promise((resolve, reject) => {
    let resolved = false
    const sock = tls.connect({
      host: relay.host,
      port: relay.port,
      servername: relay.sni,
      rejectUnauthorized: false,
    }, () => {
      sock.setKeepAlive(true, 15000)
      sock.write([
        `CONNECT ${targetHostPort} HTTP/1.1`,
        `Host: ${targetHostPort}`,
        `Proxy-Authorization: ${XBOX_AUTH}`,
        'Proxy-Connection: keep-alive',
        '', ''
      ].join('\r\n'))
    })

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true
        sock.destroy()
        reject(new Error(`Timeout connecting to ${relay.name}`))
      }
    }, timeoutMs)

    sock.once('data', (chunk) => {
      if (!resolved) {
        resolved = true
        clearTimeout(timer)
        const text = chunk.toString('utf8')
        const statusLine = text.split('\r\n')[0] || ''
        if (statusLine.includes(' 200 ')) {
          if (updateActiveRoute) activeBridgeRoute = `${relay.name} (${relay.host})`
          resolve(sock)
        } else {
          sock.destroy()
          reject(new Error(`${relay.name} rejected CONNECT: ${statusLine}`))
        }
      }
    })

    sock.once('error', (err) => {
      if (!resolved) {
        resolved = true
        clearTimeout(timer)
        sock.destroy()
        reject(err)
      }
    })
  })
}

function connectViaLocalAgDns(targetHostPort, port, timeoutMs = 2000, updateActiveRoute = true) {
  return new Promise((resolve, reject) => {
    let resolved = false
    const sock = net.connect({ host: '127.0.0.1', port }, () => {
      sock.setKeepAlive(true, 15000)
      sock.write(`CONNECT ${targetHostPort} HTTP/1.1\r\nHost: ${targetHostPort}\r\n\r\n`)
    })
    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true
        sock.destroy()
        reject(new Error(`Timeout ag_dns:${port}`))
      }
    }, timeoutMs)
    sock.once('data', (chunk) => {
      if (!resolved) {
        resolved = true
        clearTimeout(timer)
        if (chunk.toString('utf8').includes(' 200 ')) {
          if (updateActiveRoute) activeBridgeRoute = `ag_dns.exe (127.0.0.1:${port})`
          resolve(sock)
        } else {
          sock.destroy()
          reject(new Error(`ag_dns:${port} rejected`))
        }
      }
    })
    sock.once('error', (err) => {
      if (!resolved) {
        resolved = true
        clearTimeout(timer)
        sock.destroy()
        reject(err)
      }
    })
  })
}

export async function establishNodeBridgeSocket(targetHost, targetPort) {
  // Keep legacy callers on the same externally managed bridge; this function must
  // never run a second, in-process route-selection tree.
  const socket = await connectViaRunningCloudCodeBridge(`${targetHost}:${targetPort}`, 53130, 5000)
  activeBridgeRoute = (await queryActiveBridgeRoute()) || activeBridgeRoute
  return socket
}

export function startBuiltinNodeBridge(port = 53129) {
  // 53129 is compatibility-only: relay the raw CONNECT stream to the single router
  // at 53130. Refuse other ports so this helper cannot become a competing router.
  if (Number(port) !== 53129) return Promise.resolve(null)
  if (builtinNodeBridgeServer) return Promise.resolve(builtinNodeBridgeServer)

  return new Promise((resolve) => {
    const server = net.createServer((clientSocket) => {
      const upstreamSocket = net.connect({ host: '127.0.0.1', port: 53130 })
      clientSocket.on('error', () => upstreamSocket.destroy())
      upstreamSocket.on('error', () => clientSocket.destroy())
      clientSocket.on('close', () => upstreamSocket.destroy())
      upstreamSocket.on('close', () => clientSocket.destroy())
      clientSocket.pipe(upstreamSocket)
      upstreamSocket.pipe(clientSocket)
    })

    server.on('error', () => resolve(null))
    server.listen(53129, '127.0.0.1', () => {
      builtinNodeBridgeServer = server
      resolve(server)
    })
  })
}

async function stopBuiltinNodeBridge() {
  if (!builtinNodeBridgeServer) return
  const srv = builtinNodeBridgeServer
  builtinNodeBridgeServer = null
  try {
    if (typeof srv.closeAllConnections === 'function') {
      srv.closeAllConnections()
    }
  } catch {}
  await new Promise((resolve) => {
    srv.close(() => resolve())
    setTimeout(resolve, 500)
  })
}

async function queryBridgeStatus() {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:53130/status', { timeout: 600 }, (res) => {
      let data = ''
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try {
          const j = JSON.parse(data)
          if (j && j.ok === true && j.port === 53130 && (j.bridgeBuildId === 'dsh-antigravity-unified-connect-v7' || j.bridgeBuildId === 'dsh-antigravity-unified-connect-v6' || j.bridgeBuildId === 'dsh-antigravity-unified-connect-v8')) return resolve(j)
        } catch {}
        resolve(null)
      })
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

async function queryActiveBridgeRoute() {
  const status = await queryBridgeStatus()
  return status?.activeRoute || null
}

async function reportBridgeApiResult(result, stage, routeIdOverride = null, diagnosticId = null) {
  const status = routeIdOverride ? null : await queryBridgeStatus()
  const routeId = routeIdOverride || status?.activeRouteId
  if (!routeId && !diagnosticId) return
  const body = JSON.stringify({
    ...(routeId ? { routeId } : {}),
    ...(diagnosticId ? { diagnosticId } : {}),
    ok: result.ok === true,
    stage,
    shortStatus: result.shortStatus,
    status: result.status,
  })
  await new Promise((resolve) => {
    const req = http.request({
      host: '127.0.0.1',
      port: 53130,
      path: '/route-result',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 700,
    }, () => resolve())
    req.on('error', resolve)
    req.on('timeout', () => { req.destroy(); resolve() })
    req.end(body)
  })
}

let externalBridgeChild = null
let lastExternalBridgeSpawnAttempt = 0

function startExternalBridgeHidden() {
  if (externalBridgeChild && !externalBridgeChild.killed && externalBridgeChild.exitCode === null) return
  const now = Date.now()
  if (now - lastExternalBridgeSpawnAttempt < 15000) return
  lastExternalBridgeSpawnAttempt = now
  const bridgePath = path.join(BIN_DIR, 'xbox-failover-bridge.mjs')
  if (!fs.existsSync(bridgePath)) return
  try {
    const child = spawn(process.execPath, [bridgePath], {
      cwd: BIN_DIR,
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    })
    child.unref()
    externalBridgeChild = child
    child.on('exit', () => { externalBridgeChild = null })
  } catch {
    externalBridgeChild = null
  }
}

export async function ensureAntigravityServices(forceRestart = false) {
  const dynamicAgPort = getAgDnsPort()
  const agExeOnline = (await checkTcpPort(dynamicAgPort)) || (await checkTcpPort(48129)) || (await checkTcpPort(44129)) || (await checkTcpPort(43129))
  if (!agExeOnline) {
    startAgDnsHidden()
  }

  let bridgeStatus = await queryBridgeStatus()
  if (!bridgeStatus) {
    // A legacy copy of the bridge can still own 53130 after a plugin update. Replace
    // only a listener whose process command line identifies it as this bridge script.
    stopStaleBridgeListenerIfOwned()
    startExternalBridgeHidden()
    for (let i = 0; i < 20; i++) {
      await new Promise(r => setTimeout(r, 100))
      bridgeStatus = await queryBridgeStatus()
      if (bridgeStatus) break
    }
  }

  // Make the active auth file available before syncing it, then restart cli-proxy-api
  // whenever its on-disk proxy settings change. Editing JSON/YAML alone does not reload
  // settings already held in a running process.
  getActiveAuthFile()
  const proxyConfigsChanged = syncProxyConfigs(53130)

  let cliOnline = await checkTcpPort(8317)
  const listenerSnapshotBeforeStart = getWindowsListenerDiagnostics()
  const preRestartDiagnostics = getProxyRoutingDiagnostics(listenerSnapshotBeforeStart)
  // If the running process predates config.yaml, it may still hold an old proxy-url
  // even when the file already contains 53130. Relaunch it once to reload that file.
  const cliProcessConfigStale = listenerSnapshotBeforeStart.supported && preRestartDiagnostics.cliProcessStartedAfterConfig === false
  const restartCliProxy = forceRestart || proxyConfigsChanged || cliProcessConfigStale
  const listenersBeforeRestart = restartCliProxy ? listenerSnapshotBeforeStart : null
  const previousCliListenerPids = (listenersBeforeRestart?.listeners || [])
    .filter((listener) => Number(listener.port) === 8317 && listener.cliProxyExe === true)
    .map((listener) => Number(listener.pid))
  if (restartCliProxy) {
    if (cliOnline || isCliProxyRunningInOs()) {
      try {
        execFileSync('taskkill.exe', ['/F', '/IM', 'cli-proxy-api.exe'], { stdio: 'ignore', windowsHide: true })
      } catch {}
      // Wait until the old process has exited and released its listener (up to 3s).
      for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 100))
        const processStillRunning = isCliProxyRunningInOs()
        const portStillOpen = await checkTcpPort(8317, '127.0.0.1', 200)
        if (!processStillRunning && !portStillOpen) break
      }
      cliProxyChild = null
      cliOnline = false
    }
    lastCliProxySpawnAttempt = 0
  }
  if (!cliOnline) {
    startCliProxyHidden()
    for (let i = 0; i < 15; i++) {
      await new Promise(r => setTimeout(r, 200))
      if (await checkTcpPort(8317)) {
        cliOnline = true
        break
      }
    }
  }

  const bridge53130Online = Boolean(bridgeStatus)
  const currentActiveRoute = bridgeStatus?.activeRoute || null
  const listenerDiagnostics = getWindowsListenerDiagnostics()
  let cliRestartVerified = restartCliProxy ? null : true
  if (restartCliProxy && listenersBeforeRestart?.supported && listenerDiagnostics.supported) {
    const currentCliListenerPids = listenerDiagnostics.listeners
      .filter((listener) => Number(listener.port) === 8317 && listener.cliProxyExe === true)
      .map((listener) => Number(listener.pid))
    cliRestartVerified = currentCliListenerPids.length > 0 && currentCliListenerPids.every((pid) => !previousCliListenerPids.includes(pid))
  }
  const routingDiagnostics = getProxyRoutingDiagnostics(listenerDiagnostics, cliRestartVerified)

  return {
    activeRoute: currentActiveRoute,
    bridge: {
      name: 'xbox-failover-bridge',
      port: 53130,
      online: bridge53130Online,
      bridgeBuildId: bridgeStatus?.bridgeBuildId || null,
      activeRoute: currentActiveRoute,
      lastTransportRoute: bridgeStatus?.lastTransportRoute || null,
      lastApiResult: bridgeStatus?.lastApiResult || null,
      lastRouteFailure: bridgeStatus?.lastRouteFailure || null,
    },
    agDns: {
      name: bridge53130Online ? 'xbox-failover-bridge' : 'ag_dns.exe',
      port: bridge53130Online ? 53130 : getAgDnsPort(),
      online: bridge53130Online || agExeOnline,
    },
    cliProxy: {
      name: 'cli-proxy-api.exe',
      port: 8317,
      online: cliOnline,
      upstream: 'http://127.0.0.1:53130',
      listenerOwnedByExpectedProcess: routingDiagnostics.listenerChecks.cliProxy8317OwnedByCliProxyApi,
    },
    routingDiagnostics,
  }
}

async function pingLocalProxyToRefreshToken() {
  return new Promise((resolve) => {
    const req = http.request({
      host: '127.0.0.1',
      port: 8317,
      path: '/v1/models',
      method: 'GET',
      headers: { Authorization: 'Bearer antigravity-local-key' },
      timeout: 4000,
    }, (res) => {
      res.resume()
      res.on('end', resolve)
    })
    req.on('error', () => resolve())
    req.on('timeout', () => { req.destroy(); resolve() })
    req.end()
  })
}

async function requestGoogleQuota(accessToken, proxyUrlStr, projectId = 'aicode-consumers') {
  const targetHost = 'daily-cloudcode-pa.googleapis.com'
  const targetPort = 443
  const reqBody = JSON.stringify({ project: projectId || 'aicode-consumers' })

  const attemptConnect = (port) => new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: Number(port),
      method: 'CONNECT',
      path: `${targetHost}:${targetPort}`,
      timeout: 15000,
    })

    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy()
        return reject(new Error(`Proxy CONNECT status ${res.statusCode}`))
      }
      const tlsSocket = tls.connect({
        socket,
        servername: targetHost,
      }, () => {
        const lines = [
          'POST /v1internal:retrieveUserQuotaSummary HTTP/1.1',
          `Host: ${targetHost}`,
          `Authorization: Bearer ${accessToken}`,
          'Content-Type: application/json',
          'User-Agent: antigravity/2.16.0',
          `Content-Length: ${Buffer.byteLength(reqBody)}`,
          'Connection: close',
          '',
          reqBody,
        ].join('\r\n')
        tlsSocket.write(lines)
      })

      const chunks = []
      tlsSocket.on('data', c => chunks.push(c))
      tlsSocket.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8')
        const statusLine = raw.split('\r\n')[0] || ''
        if (statusLine.includes(' 401 ') || statusLine.includes(' 403 ')) {
          const err = new Error('Unauthorized')
          err.code = 401
          return reject(err)
        }
        const splitIdx = raw.indexOf('\r\n\r\n')
        const body = splitIdx !== -1 ? raw.slice(splitIdx + 4) : raw
        const jsonStart = body.indexOf('{')
        const jsonEnd = body.lastIndexOf('}')
        if (jsonStart !== -1 && jsonEnd !== -1) {
          try {
            resolve(JSON.parse(body.slice(jsonStart, jsonEnd + 1)))
          } catch (e) {
            reject(e)
          }
        } else {
          reject(new Error('Invalid quota response'))
        }
      })
      tlsSocket.on('error', reject)
    })

    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error('Proxy timeout')) })
    req.end()
  })

  // All Cloud Code calls made by this plugin use the same bridge as cli-proxy-api.
  // Port 53129 is compatibility-only and must never be a separate routing decision.
  return attemptConnect(53130)
}

function buildQuotaGroups(raw) {
  if (Array.isArray(raw?.groups) && raw.groups.length > 0) return raw.groups
  const modelsObj = raw?.models || {}
  const defs = [
    { id: 'claude-gpt', label: 'Claude 4.6 & GPT-OSS', match: (k) => /claude|gpt-oss/i.test(k) },
    { id: 'gemini-pro', label: 'Gemini 3.1 Pro', match: (k) => /gemini.*pro/i.test(k) },
    { id: 'gemini-flash', label: 'Gemini 3 Flash', match: (k) => /gemini.*flash/i.test(k) && !/image/i.test(k) },
    { id: 'gemini-image', label: 'Gemini 3.1 Image', match: (k) => /image/i.test(k) },
  ]
  const out = []
  for (const def of defs) {
    const matched = []
    let minFrac = 1
    let resetTime = null
    for (const [key, val] of Object.entries(modelsObj)) {
      if (!def.match(key)) continue
      const q = val?.quotaInfo
      if (!q) continue
      const frac = typeof q.remainingFraction === 'number' ? q.remainingFraction : 1
      if (frac < minFrac) minFrac = frac
      if (q.resetTime && (!resetTime || q.resetTime < resetTime)) resetTime = q.resetTime
      matched.push({
        id: key,
        displayName: val.displayName || key,
        remainingPercent: Math.round(frac * 100),
        resetTime: q.resetTime || null,
      })
    }
    if (matched.length > 0) {
      out.push({
        id: def.id,
        label: def.label,
        remainingPercent: Math.round(minFrac * 100),
        resetTime,
        models: matched,
      })
    }
  }
  return out
}

let cachedData = null
let cachedAt = 0

export async function fetchAntigravityQuota(force = false, restartServices = false) {
  const services = await ensureAntigravityServices(restartServices)
  const accounts = listAccounts()
  const now = Date.now()
  if (!force && !restartServices && cachedData && now - cachedAt < 20000) {
    return { ...cachedData, services, accounts }
  }
  const authPath = getActiveAuthFile()
  if (!authPath || !fs.existsSync(authPath)) {
    throw new Error('Auth file not found in ~/.cli-proxy-api')
  }
  let auth
  try {
    auth = JSON.parse(fs.readFileSync(authPath, 'utf8'))
  } catch {
    throw new Error('Файл авторизации повреждён (invalid JSON)')
  }
  if (auth.expired && Date.parse(auth.expired) < Date.now() + 600000) {
    await pingLocalProxyToRefreshToken()
    try {
      auth = JSON.parse(fs.readFileSync(authPath, 'utf8'))
    } catch {}
    ensureVaultSynced()
  }
  let raw
  try {
    raw = await requestGoogleQuota(auth.access_token, auth.proxy_url, auth.project_id)
  } catch (err) {
    await pingLocalProxyToRefreshToken()
    try {
      auth = JSON.parse(fs.readFileSync(authPath, 'utf8'))
    } catch {}
    ensureVaultSynced()
    raw = await requestGoogleQuota(auth.access_token, auth.proxy_url, auth.project_id)
  }
  const groups = buildQuotaGroups(raw)
  const activeAccounts = listAccounts()
  const activeAcc = activeAccounts.find(a => a.active) || activeAccounts[0]
  const primaryGroup = groups.find(g => (g.displayName || g.label || g.id || '').toLowerCase().includes('gemini')) || groups[0]
  const gemini5h = primaryGroup?.buckets?.find(b => b.window === '5h')
  const geminiWeekly = primaryGroup?.buckets?.find(b => b.window === 'weekly')
  const primaryPercent = gemini5h
    ? Math.round(gemini5h.remainingFraction * 100)
    : (typeof primaryGroup?.remainingPercent === 'number' ? primaryGroup.remainingPercent : 100)
  const weeklyPercent = geminiWeekly
    ? Math.round(geminiWeekly.remainingFraction * 100)
    : null
  cachedData = {
    ok: true,
    plan: 'Google AI Pro',
    email: auth.email || activeAcc?.email || '',
    activeEmail: auth.email || activeAcc?.email || '',
    updatedAt: Date.now(),
    summary: {
      primaryPercent,
      weeklyPercent,
      minPercent: primaryPercent,
      resetTime: gemini5h?.resetTime || primaryGroup?.resetTime || null,
    },
    groups,
    services,
    accounts: activeAccounts,
  }
  cachedAt = Date.now()
  return cachedData
}

async function testGoogleCloudCodeOnSocket(rawSocket, token = '', timeoutMs = 5000) {
  return new Promise((resolve) => {
    let settled = false
    let fullResponse = ''
    let tlsSocket
    const finish = (result) => {
      if (settled) return
      settled = true
      try { tlsSocket?.destroy() } catch {}
      try { if (!tlsSocket) rawSocket?.destroy() } catch {}
      resolve(result)
    }
    const classify = () => {
      const firstLine = fullResponse.split('\r\n')[0] || ''
      const match = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i)
      const code = match ? Number(match[1]) : 0
      const lower = fullResponse.toLowerCase()
      if (code === 200) return { ok: true, warning: false, shortStatus: 'Gemini OK', status: 'Cloud Code 200 OK', error: null }
      const locationRejected = lower.includes('user location is not supported') || /location.{0,80}not supported|not supported.{0,80}location/.test(lower)
      if (code === 400 && locationRejected) {
        return { ok: false, warning: false, shortStatus: '400 location', status: 'Google rejected location (400 FAILED_PRECONDITION)', error: 'User location is not supported for the API use.' }
      }
      if (code === 401 || code === 403) return { ok: false, warning: true, shortStatus: `Auth ${code}`, status: `Google reached but returned HTTP ${code}; authorization may need refresh`, error: firstLine }
      if (code === 429) return { ok: false, warning: true, shortStatus: '429 limit', status: 'Google returned HTTP 429 (rate/capacity limit)', error: firstLine }
      if (code === 502 || code === 503 || code === 504) return { ok: false, warning: true, shortStatus: `${code} upstream`, status: `Google/upstream returned HTTP ${code}`, error: firstLine }
      if (code) return { ok: false, warning: code >= 500, shortStatus: `HTTP ${code}`, status: firstLine, error: fullResponse.slice(0, 500) }
      return { ok: false, warning: false, shortStatus: 'No HTTP', status: 'No valid HTTP response', error: fullResponse.slice(0, 500) || 'Connection closed without an HTTP response' }
    }

    try {
      tlsSocket = tls.connect({
        socket: rawSocket,
        servername: 'daily-cloudcode-pa.googleapis.com',
        // Keep normal certificate validation enabled for these tests. Do not send OAuth tokens to an unverified endpoint.
        rejectUnauthorized: true,
      })
    } catch (err) {
      finish({ ok: false, warning: false, shortStatus: 'TLS failed', status: 'TLS connection failed', error: err.message })
      return
    }
    const timer = setTimeout(() => finish({ ok: false, warning: true, shortStatus: 'Timeout', status: 'Google Cloud Code request timed out', error: 'Timed out waiting for Cloud Code' }), timeoutMs)
    const finishAndClear = (result) => { clearTimeout(timer); finish(result) }
    tlsSocket.setTimeout(timeoutMs, () => finishAndClear({ ok: false, warning: true, shortStatus: 'Timeout', status: 'Google Cloud Code request timed out', error: 'Timed out waiting for Cloud Code' }))
    tlsSocket.once('secureConnect', () => {
      const body = JSON.stringify({ project: 'aicode-consumers' })
      const headers = [
        'POST /v1internal:fetchAvailableModels HTTP/1.0',
        'Host: daily-cloudcode-pa.googleapis.com',
        token ? `Authorization: Bearer ${token}` : '',
        'Content-Type: application/json',
        'User-Agent: antigravity/2.16.0',
        `Content-Length: ${Buffer.byteLength(body)}`,
        'Connection: close',
      ].filter(Boolean)
      tlsSocket.write(headers.join('\r\n') + '\r\n\r\n' + body)
    })
    tlsSocket.on('data', (chunk) => {
      fullResponse += chunk.toString('utf8')
      const firstLine = fullResponse.split('\r\n')[0] || ''
      const match = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i)
      const code = match ? Number(match[1]) : 0
      const lower = fullResponse.toLowerCase()
      if (code === 200) finishAndClear(classify())
      else if (code === 400 && (lower.includes('user location is not supported') || /location.{0,80}not supported|not supported.{0,80}location/.test(lower))) finishAndClear(classify())
      else if ([401, 403, 429, 502, 503, 504].includes(code)) finishAndClear(classify())
      else if (fullResponse.length > 16384) finishAndClear(classify())
    })
    tlsSocket.once('end', () => finishAndClear(classify()))
    tlsSocket.once('error', (err) => finishAndClear({ ok: false, warning: false, shortStatus: 'TLS/error', status: 'TLS/connection error', error: err.message }))
  })
}

async function testGeminiGenerationOnSocket(rawSocket, token = '', timeoutMs = 12000) {
  return new Promise((resolve) => {
    let settled = false
    let fullResponse = ''
    let tlsSocket
    const finish = (result) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { tlsSocket?.destroy() } catch {}
      try { if (!tlsSocket) rawSocket?.destroy() } catch {}
      resolve(result)
    }
    const classify = () => {
      const headerEnd = fullResponse.indexOf('\r\n\r\n')
      const headerText = headerEnd >= 0 ? fullResponse.slice(0, headerEnd) : fullResponse
      const firstLine = headerText.split('\r\n')[0] || ''
      const match = firstLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i)
      const code = match ? Number(match[1]) : 0
      const lower = fullResponse.toLowerCase()
      if (code === 200) {
        const hasGenerationBody = headerEnd >= 0 && /candidates|response/i.test(fullResponse.slice(headerEnd + 4))
        if (hasGenerationBody) return { ok: true, warning: false, shortStatus: 'Gemini generation OK', status: 'HTTP 200: real Gemini generation succeeded', error: null }
        return { ok: false, warning: false, shortStatus: '200 no payload', status: 'Google returned HTTP 200 but no recognizable generation payload', error: 'Generation response did not contain a recognizable candidates/response body' }
      }
      const locationRejected = lower.includes('user location is not supported') || /location.{0,80}not supported|not supported.{0,80}location/.test(lower)
      if (code === 400 && locationRejected) {
        return { ok: false, warning: false, shortStatus: '400 location', status: 'Google rejected the Gemini request with a location/eligibility error', error: 'User location is not supported for the API use.' }
      }
      if (code === 401 || code === 403) return { ok: false, warning: true, shortStatus: `Auth ${code}`, status: `Google reached, but generation returned HTTP ${code}`, error: firstLine }
      if (code === 429) return { ok: false, warning: true, shortStatus: '429 limit', status: 'Google returned HTTP 429 (rate/capacity limit)', error: firstLine }
      if ([500, 502, 503, 504].includes(code)) return { ok: false, warning: true, shortStatus: `${code} upstream`, status: `Gemini generation returned HTTP ${code}`, error: fullResponse.slice(headerEnd >= 0 ? headerEnd + 4 : 0, 800) || firstLine }
      if (code) return { ok: false, warning: code >= 500, shortStatus: `HTTP ${code}`, status: firstLine, error: fullResponse.slice(headerEnd >= 0 ? headerEnd + 4 : 0, 800) || firstLine }
      return { ok: false, warning: false, shortStatus: 'No HTTP', status: 'No valid HTTP response from Gemini generation endpoint', error: fullResponse.slice(0, 800) || 'Connection closed without an HTTP response' }
    }
    let timer
    try {
      tlsSocket = tls.connect({
        socket: rawSocket,
        servername: 'daily-cloudcode-pa.googleapis.com',
        rejectUnauthorized: true,
      })
    } catch (err) {
      finish({ ok: false, warning: false, shortStatus: 'TLS failed', status: 'TLS connection failed', error: err.message })
      return
    }
    timer = setTimeout(() => finish({ ok: false, warning: true, shortStatus: 'Timeout', status: 'Timed out waiting for real Gemini generation response', error: 'Timeout waiting for /v1internal:generateContent' }), timeoutMs)
    tlsSocket.setTimeout(timeoutMs, () => finish({ ok: false, warning: true, shortStatus: 'Timeout', status: 'Timed out waiting for real Gemini generation response', error: 'Timeout waiting for /v1internal:generateContent' }))
    tlsSocket.once('secureConnect', () => {
      const body = JSON.stringify({
        project: 'aicode-consumers',
        model: 'gemini-3.8-flash-high',
        request: {
          contents: [{ role: 'user', parts: [{ text: 'Reply with exactly: ROUTE_TEST_OK' }] }],
          generationConfig: { temperature: 0, maxOutputTokens: 8 },
        },
        userAgent: 'antigravity',
        requestId: randomBytes(8).toString('hex'),
      })
      const headers = [
        'POST /v1internal:generateContent HTTP/1.0',
        'Host: daily-cloudcode-pa.googleapis.com',
        `Authorization: Bearer ${token}`,
        'Content-Type: application/json',
        'Accept: application/json',
        'User-Agent: antigravity/2.16.0',
        'X-Goog-Api-Client: google-cloud-sdk vscode_cloudshelleditor/0.1',
        'Client-Metadata: {"ideType":"ANTIGRAVITY","platform":"WINDOWS","pluginType":"GEMINI"}',
        `Content-Length: ${Buffer.byteLength(body)}`,
        'Connection: close',
      ]
      tlsSocket.write(headers.join('\r\n') + '\r\n\r\n' + body)
    })
    tlsSocket.on('data', (chunk) => {
      fullResponse += chunk.toString('utf8')
      if (fullResponse.length > 65536) finish(classify())
    })
    tlsSocket.once('end', () => finish(classify()))
    tlsSocket.once('error', (err) => finish({ ok: false, warning: false, shortStatus: 'TLS/error', status: 'TLS/connection error during Gemini request', error: err.message }))
  })
}

function connectViaRunningCloudCodeBridge(targetHostPort, bridgePort = 53130, timeoutMs = 5000, diagnosticId = null) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: bridgePort })
    let settled = false
    let buffer = Buffer.alloc(0)
    const cleanup = () => {
      clearTimeout(timer)
      socket.removeListener('connect', onConnect)
      socket.removeListener('data', onData)
      socket.removeListener('error', onError)
    }
    const finishError = (error) => {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      reject(error instanceof Error ? error : new Error(String(error)))
    }
    const onConnect = () => {
      socket.setKeepAlive(true, 15000)
      const diagnosticHeader = typeof diagnosticId === 'string' && /^[a-zA-Z0-9_-]{12,64}$/u.test(diagnosticId)
        ? `X-Antigravity-Diagnostic-Id: ${diagnosticId}\r\n`
        : ''
      socket.write(`CONNECT ${targetHostPort} HTTP/1.1\r\nHost: ${targetHostPort}\r\nProxy-Connection: Keep-Alive\r\n${diagnosticHeader}\r\n`)
    }
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      const marker = buffer.indexOf('\r\n\r\n')
      if (marker < 0) {
        if (buffer.length > 8192) finishError(new Error('Oversized response from local bridge'))
        return
      }
      const headers = buffer.subarray(0, marker).toString('utf8')
      const headerLines = headers.split('\r\n')
      const firstLine = headerLines[0] || ''
      if (!/\s200\s/.test(firstLine)) {
        finishError(new Error(`Local bridge ${bridgePort} rejected CONNECT: ${firstLine || 'empty response'}`))
        return
      }
      if (settled) return
      const responseHeaders = Object.create(null)
      for (const line of headerLines.slice(1)) {
        const separator = line.indexOf(':')
        if (separator <= 0) continue
        responseHeaders[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim()
      }
      const returnedDiagnosticId = responseHeaders['x-antigravity-diagnostic-id'] || null
      let returnedLabel = null
      if (responseHeaders['x-antigravity-route-label']) {
        try { returnedLabel = decodeURIComponent(responseHeaders['x-antigravity-route-label']) } catch {}
      }
      socket.__antigravityDiagnosticRoute = responseHeaders['x-antigravity-route-id'] ? {
        id: responseHeaders['x-antigravity-route-id'],
        kind: responseHeaders['x-antigravity-route-kind'] || null,
        routingEffect: responseHeaders['x-antigravity-routing-effect'] || null,
        label: returnedLabel || responseHeaders['x-antigravity-route-id'],
        diagnosticIdAccepted: Boolean(diagnosticId && returnedDiagnosticId === diagnosticId),
      } : null
      socket.__antigravityDiagnosticIdAccepted = Boolean(diagnosticId && returnedDiagnosticId === diagnosticId)
      settled = true
      cleanup()
      socket.setKeepAlive(true, 15000)
      const rest = buffer.subarray(marker + 4)
      if (rest.length) socket.unshift(rest)
      resolve(socket)
    }
    const onError = (err) => finishError(err)
    const timer = setTimeout(() => finishError(new Error(`Timeout waiting for CONNECT on 127.0.0.1:${bridgePort}`)), timeoutMs)
    socket.once('connect', onConnect)
    socket.on('data', onData)
    socket.once('error', onError)
  })
}

async function testSelectedGeminiGeneration() {
  const startedAt = Date.now()
  const serviceState = await ensureAntigravityServices(false)
  const routePreference = readCloudCodeRoutePreference()
  const diagnostics = serviceState.routingDiagnostics
  const listenerInspectionFailed = diagnostics?.listenerInspectionSupported && (
    !diagnostics.listenerChecks?.bridge53130OwnedByBridge ||
    !diagnostics.listenerChecks?.compat53129SharesBridgePid ||
    !diagnostics.listenerChecks?.cliProxy8317OwnedByCliProxyApi
  )
  const cliRestartFailed = diagnostics?.listenerInspectionSupported && diagnostics.cliRestartVerified === false
  const cliConfigReloadFailed = diagnostics?.listenerInspectionSupported && diagnostics.cliProcessStartedAfterConfig === false
  if (!serviceState.bridge?.online || !serviceState.cliProxy?.online || !diagnostics?.filesMatchExpected || listenerInspectionFailed || cliRestartFailed || cliConfigReloadFailed) {
    return {
      ok: false,
      warning: false,
      routePreference,
      status: 'Preflight failed; generation request was not sent',
      shortStatus: 'Route wiring mismatch',
      error: !serviceState.bridge?.online
        ? 'Port 53130 is not serving the current bridge build; no generation request was sent.'
        : !serviceState.cliProxy?.online || listenerInspectionFailed || cliRestartFailed || cliConfigReloadFailed
          ? cliRestartFailed || cliConfigReloadFailed
            ? 'The active cli-proxy-api process could not be confirmed to have loaded the current config.yaml; no generation request was sent.'
            : listenerInspectionFailed && (!diagnostics.listenerChecks?.bridge53130OwnedByBridge || !diagnostics.listenerChecks?.compat53129SharesBridgePid)
              ? 'Ports 53129/53130 are not confirmed as one bridge process; no generation request was sent.'
              : 'cli-proxy-api on port 8317 is not confirmed as the active local API process; no generation request was sent.'
          : 'proxy_url files do not both point to http://127.0.0.1:53130; no generation request was sent.',
      routingDiagnostics: diagnostics,
      latencyMs: Date.now() - startedAt,
      testedAt: new Date().toISOString(),
    }
  }
  const authPath = getActiveAuthFile()
  if (!authPath || !fs.existsSync(authPath)) {
    return { ok: false, routePreference, status: 'Auth file not found', shortStatus: 'No auth', error: 'No active Antigravity auth file was found', routingDiagnostics: diagnostics, latencyMs: Date.now() - startedAt }
  }
  let token = ''
  try { token = JSON.parse(fs.readFileSync(authPath, 'utf8')).access_token || '' } catch {}
  if (!token) {
    return { ok: false, routePreference, status: 'Access token missing', shortStatus: 'No token', error: 'The active auth file does not contain an access token', routingDiagnostics: diagnostics, latencyMs: Date.now() - startedAt }
  }
  let socket
  let route = null
  const diagnosticId = randomBytes(12).toString('hex')
  let diagnosticRoute = null
  try {
    // Use exactly the bridge configured for cli-proxy-api and bind the API result to this tunnel.
    socket = await connectViaRunningCloudCodeBridge('daily-cloudcode-pa.googleapis.com:443', 53130, 5000, diagnosticId)
    diagnosticRoute = socket.__antigravityDiagnosticRoute || null
    if (!socket.__antigravityDiagnosticIdAccepted || diagnosticRoute?.diagnosticIdAccepted !== true) {
      throw new Error('Bridge did not acknowledge the diagnostic ID on this CONNECT; generation was not sent. Run routing diagnostics to inspect the last diagnostic CONNECT.')
    }
    if (!diagnosticRoute?.id || !diagnosticRoute?.kind || !diagnosticRoute?.routingEffect) {
      throw new Error('Bridge accepted the diagnostic ID but did not return a verified route identity; generation was not sent.')
    }
    route = diagnosticRoute.label
    const result = await testGeminiGenerationOnSocket(socket, token, 12000)
    socket = null
    await reportBridgeApiResult(result, 'generation', diagnosticRoute.id, diagnosticId)
    return { ...result, routePreference, route, routingDiagnostics: serviceState.routingDiagnostics, latencyMs: Date.now() - startedAt, testedAt: new Date().toISOString(), model: 'gemini-3.8-flash-high' }
  } catch (err) {
    return { ok: false, routePreference, route, routingDiagnostics: serviceState.routingDiagnostics, status: 'Route connection failed before Gemini request', shortStatus: 'Route failed', error: err.message, latencyMs: Date.now() - startedAt, testedAt: new Date().toISOString(), model: 'gemini-3.8-flash-high' }
  } finally {
    try { socket?.destroy() } catch {}
  }
}

async function testOneRouteWithCloudCode(r, token = '') {
  const t0 = Date.now()
  if (r.type === 'direct') {
    try {
      const s = await connectTcpSocket(r.host, r.port, 2500)
      s.destroy()
      return { ...r, ok: false, warning: true, latencyMs: Date.now() - t0, shortStatus: 'OAuth only', status: 'OAuth connectivity only; not a Gemini Cloud Code route', error: null }
    } catch (err) {
      return { ...r, ok: false, warning: false, latencyMs: Date.now() - t0, shortStatus: 'Unavailable', status: 'OAuth route unavailable', error: err.message }
    }
  }

  if (r.type === 'doh') {
    let addresses = []
    let lastError = null
    try {
      addresses = await queryDohA(r, 'daily-cloudcode-pa.googleapis.com', 2500)
    } catch (err) {
      return { ...r, ok: false, warning: false, latencyMs: Date.now() - t0, shortStatus: 'DoH failed', status: 'DoH query failed', error: err.message, addresses: [] }
    }
    let best = null
    for (const address of addresses.slice(0, 2)) {
      let sock
      try {
        sock = await connectTcpSocket(address, 443, 1800)
        const cloud = await testGoogleCloudCodeOnSocket(sock, token, 4500)
        sock = null // testGoogleCloudCodeOnSocket owns/destroys the socket
        const candidate = {
          ...r, ...cloud, latencyMs: Date.now() - t0,
          dnsAddresses: addresses,
          status: `${cloud.status}; DNS A: ${addresses.join(', ')}`,
          error: cloud.error,
        }
        if (candidate.ok) return candidate
        if (!best || (cloud.warning && !best.warning)) best = candidate
      } catch (err) {
        lastError = err
      } finally {
        try { sock?.destroy() } catch {}
      }
    }
    if (best) return best
    return { ...r, ok: false, warning: false, latencyMs: Date.now() - t0, shortStatus: 'TCP failed', status: `DNS A: ${addresses.join(', ')}; TCP/TLS failed`, error: lastError?.message || 'No resolved address was reachable', dnsAddresses: addresses }
  }

  let sock
  try {
    if (r.type === 'xbox') {
      sock = await connectViaXboxRelay({ host: r.host, port: r.port, sni: r.sni, name: r.name }, 'daily-cloudcode-pa.googleapis.com:443', 2500, false)
    } else if (r.type === 'karing-proxy') {
      sock = await connectViaSocks5Proxy('127.0.0.1', r.port, 'daily-cloudcode-pa.googleapis.com', 443, 3000)
    } else if (r.type === 'ag_dns') {
      const safe = isAgDnsSafeToUse()
      if (!safe) return { ...r, ok: false, warning: true, latencyMs: Date.now() - t0, shortStatus: 'RU/unsafe exit', status: 'Skipped: gate reports a Russian/direct or unsafe exit', error: 'ag_dns is excluded from Cloud Code routing when its gate reports RU or direct exit' }
      sock = await connectViaLocalAgDns('daily-cloudcode-pa.googleapis.com:443', r.port, 1800, false)
    } else {
      sock = await connectTcpSocket(r.host, r.port, 2200)
    }
    const cloud = await testGoogleCloudCodeOnSocket(sock, token, 4500)
    sock = null
    return { ...r, ...cloud, latencyMs: Date.now() - t0, status: cloud.status, error: cloud.error }
  } catch (err) {
    return { ...r, ok: false, warning: false, latencyMs: Date.now() - t0, shortStatus: r.type === 'xbox' ? 'Relay/TLS failed' : r.type === 'karing-proxy' ? 'Karing SOCKS5 failed' : 'TCP failed', status: 'Route connection failed', error: err.message }
  } finally {
    try { sock?.destroy() } catch {}
  }
}

async function testAllBypassRoutes(token = '') {
  const routesToTest = [
    { id: 'karing-proxy', name: 'Karing Full Proxy', host: '127.0.0.1', port: 3066, type: 'karing-proxy' },
    ...DOH_RESOLVERS.map(r => ({ ...r, name: `${r.name} (DoH)`, host: new URL(r.url).hostname, port: 443, type: 'doh' })),
    { id: 'ag-dns', name: 'ag_dns (Локальный)', host: '127.0.0.1', port: getAgDnsPort() || 47129, type: 'ag_dns' },
    { id: 'oauth-direct', name: 'OAuth2 Direct', host: 'oauth2.googleapis.com', port: 443, type: 'direct' },
  ]
  // Keep route scans bounded: a 3-worker pool avoids firing many authenticated Cloud Code requests at once.
  const results = new Array(routesToTest.length)
  let nextIndex = 0
  const worker = async () => {
    while (true) {
      const i = nextIndex++
      if (i >= routesToTest.length) return
      results[i] = await testOneRouteWithCloudCode(routesToTest[i], token)
    }
  }
  await Promise.all(Array.from({ length: Math.min(3, routesToTest.length) }, () => worker()))
  return results
}

function queryLocalBridgeJson(pathname, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port: 53130, path: pathname, timeout: timeoutMs, headers: { Accept: 'application/json' } }, (res) => {
      const chunks = []
      let bytes = 0
      res.on('data', (chunk) => {
        bytes += chunk.length
        if (bytes > 65536) {
          req.destroy(new Error('Bridge diagnostic response exceeded 64 KiB'))
          return
        }
        chunks.push(chunk)
      })
      res.on('end', () => {
        try {
          const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'))
          if (res.statusCode < 200 || res.statusCode >= 300) reject(new Error(payload.error || `Bridge diagnostic returned HTTP ${res.statusCode}`))
          else resolve(payload)
        } catch (error) { reject(error) }
      })
    })
    req.on('timeout', () => req.destroy(new Error('Bridge diagnostic timed out')))
    req.on('error', reject)
  })
}

export async function testAntigravityConnection() {
  const t0 = Date.now()
  const checks = {
    cliProxy: { ok: false, latencyMs: 0 },
    bridge: { ok: false, latencyMs: 0 },
    googleApi: { ok: false, latencyMs: 0, status: null, relay: null },
  }

  // 1. Проверяем локальный cli-proxy-api (:8317)
  const tCli0 = Date.now()
  try {
    const cliOk = await checkTcpPort(8317, '127.0.0.1', 800)
    checks.cliProxy = { ok: cliOk, latencyMs: Date.now() - tCli0 }
  } catch {
    checks.cliProxy = { ok: false, latencyMs: Date.now() - tCli0 }
  }

  // 2. Проверяем локальный мост (:53130 / :53129)
  const tBr0 = Date.now()
  let activeRoute = (await queryActiveBridgeRoute()) || activeBridgeRoute
  try {
    const brOk = Boolean(await queryBridgeStatus())
    checks.bridge = { ok: brOk, latencyMs: Date.now() - tBr0, activeRoute }
  } catch {
    checks.bridge = { ok: false, latencyMs: Date.now() - tBr0, activeRoute }
  }

  // 3. Проверяем сквозное соединение с Google CloudCode API с честным определением статуса
  const tG0 = Date.now()
  let token = ''
  try {
    const authPath = getActiveAuthFile()
    if (authPath && fs.existsSync(authPath)) {
      try {
        const a = JSON.parse(fs.readFileSync(authPath, 'utf8'))
        token = a.access_token || ''
      } catch {}
    }

    const diagnosticId = randomBytes(12).toString('hex')
    const rawSock = await connectViaRunningCloudCodeBridge('daily-cloudcode-pa.googleapis.com:443', 53130, 5000, diagnosticId)
    const diagnosticRoute = rawSock.__antigravityDiagnosticRoute || null
    if (!rawSock.__antigravityDiagnosticIdAccepted || diagnosticRoute?.diagnosticIdAccepted !== true || !diagnosticRoute?.id) {
      rawSock.destroy()
      throw new Error('Bridge did not confirm the route identity for this diagnostic CONNECT; no API request was sent.')
    }
    const routeForProbe = diagnosticRoute.label || activeRoute
    const testRes = await testGoogleCloudCodeOnSocket(rawSock, token, 5000)
    await reportBridgeApiResult(testRes, 'availability', diagnosticRoute.id, diagnosticId)

    checks.googleApi = {
      ok: testRes.ok,
      latencyMs: Date.now() - tG0,
      status: testRes.status,
      error: testRes.error || null,
      relay: routeForProbe,
    }
    activeRoute = routeForProbe || activeRoute
  } catch (err) {
    checks.googleApi = {
      ok: false,
      latencyMs: Date.now() - tG0,
      status: 'Ошибка подключения',
      error: err.message,
      relay: activeRoute,
    }
  }

  checks.bridge.activeRoute = activeRoute || (await queryActiveBridgeRoute()) || activeBridgeRoute
  checks.googleApi.relay = checks.googleApi.relay || activeRoute
  // Run route-by-route read-only diagnostics after the primary check.
  const allRoutes = await testAllBypassRoutes(token)
  const allOk = checks.cliProxy.ok && checks.bridge.ok && checks.googleApi.ok

  return {
    ok: allOk,
    totalLatencyMs: Date.now() - t0,
    checks,
    routes: allRoutes,
    activeRoute,
    timestamp: Date.now(),
  }
}

function ensureProfileHasAntigravityModels() {
  try {
    const dshHome = process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
    const profilesDir = path.join(dshHome, 'profiles')
    if (!fs.existsSync(profilesDir)) return

    const patchPath = path.join(PLUGIN_ROOT, 'cordis.patch.yml')
    if (!fs.existsSync(patchPath)) return
    const patchContent = fs.readFileSync(patchPath, 'utf8')
    const llmIndex = patchContent.indexOf('- id: llm-pi-ai')
    if (llmIndex === -1) return
    const llmBlock = '\n\n# Auto-configured by dsh-plugin-antigravity-quota\n' + patchContent.slice(llmIndex).trim() + '\n'

    const entries = fs.readdirSync(profilesDir, { withFileTypes: true })
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const profilePatch = path.join(profilesDir, entry.name, 'cordis.patch.yml')
      if (fs.existsSync(profilePatch)) {
        const text = fs.readFileSync(profilePatch, 'utf8')
        if (!text.includes('antigravity:')) {
          fs.appendFileSync(profilePatch, llmBlock, 'utf8')
        }
      }
    }
  } catch {}
}

export function apply(ctx) {
  ensureProfileHasAntigravityModels()
  void ensureAntigravityServices(false)
  const watchdog = setInterval(() => {
    void ensureAntigravityServices(false)
  }, 15000)
  if (typeof watchdog.unref === 'function') watchdog.unref()
  if (typeof ctx.effect === 'function') {
    ctx.effect(() => () => {
      clearInterval(watchdog)
      if (agDnsChild) {
        try { agDnsChild.kill() } catch {}
        agDnsChild = null
      }
      if (cliProxyChild) {
        try { cliProxyChild.kill() } catch {}
        cliProxyChild = null
      }
      if (builtinNodeBridgeServer) {
        try { builtinNodeBridgeServer.close() } catch {}
        builtinNodeBridgeServer = null
      }
    }, 'antigravity-quota: watchdog')
  }

  process.once('exit', () => {
    if (agDnsChild) {
      try { agDnsChild.kill() } catch {}
      agDnsChild = null
    }
    if (cliProxyChild) {
      try { cliProxyChild.kill() } catch {}
      cliProxyChild = null
    }
    if (builtinNodeBridgeServer) {
      try { builtinNodeBridgeServer.close() } catch {}
      builtinNodeBridgeServer = null
    }
  })

  ctx.inject(['webServer'], (wctx) => {
    const mount = () => {
      const ws = wctx.webServer
      if (!ws || typeof ws.register !== 'function') return () => {}
      return ws.register({
        kind: 'exact',
        path: '/api/antigravity-quota',
        handler: async (request, response) => {
          try {
            const url = new URL(request.url || '/', 'http://127.0.0.1')
            const action = url.searchParams.get('action')
            const force = url.searchParams.get('refresh') === '1'
            let result
            let freshMod
            try {
              freshMod = await import('file:///' + path.join(PLUGIN_ROOT, 'lib', 'index.js').replace(/\\/g, '/') + '?t=' + Date.now())
            } catch {
              freshMod = null
            }
            if (action === 'oauth-start') {
              const session = startBackgroundAntigravityOAuth()
              for (let i = 0; i < 30; i++) {
                if (session.authUrl || session.status === 'error') break
                await new Promise(r => setTimeout(r, 100))
              }
              if (!session.authUrl) {
                throw new Error(session.error || 'Не удалось подготовить Google OAuth URL')
              }
              result = {
                ok: true,
                status: session.status,
                state: session.state,
                authUrl: session.authUrl,
                callbackPort: session.callbackPort,
              }
            } else if (action === 'oauth-status') {
              const state = url.searchParams.get('state') || ''
              if (!oauthSession || !state || oauthSession.state !== state) {
                throw new Error('OAuth-сессия не найдена или истекла')
              }
              result = {
                ok: oauthSession.status === 'ok' || oauthSession.status === 'wait' || oauthSession.status === 'received' || oauthSession.status === 'processing',
                status: oauthSession.status,
                state: oauthSession.state,
                authUrl: oauthSession.authUrl,
                error: oauthSession.error,
                ...(oauthSession.status === 'ok' ? oauthSession.result : {}),
              }
              if (oauthSession.status === 'ok' || oauthSession.status === 'error') {
                result.accounts = oauthSession.result?.accounts || listAccounts()
              }
            } else if (action === 'oauth-cancel') {
              if (oauthSession) {
                try { oauthSession.cancel?.() } catch (_) {}
                cleanupOAuthSession()
              }
              addingAccountInProgress = false
              result = { ok: true, cancelled: true }
            } else if (action === 'ping-test') {
              result = freshMod ? await freshMod.testAntigravityConnection() : await testAntigravityConnection()
            } else if (action === 'gemini-test') {
              result = await testSelectedGeminiGeneration()
            } else if (action === 'geohide-us-doh-probe') {
              result = await queryLocalBridgeJson('/geohide-us-doh-probe', 20000)
            } else if (action === 'open-logs') {
              const baseDir = path.join(os.homedir(), 'AppData', 'Local', 'AGUnlocker')
              const logsPath = path.join(baseDir, 'logs')
              try {
                if (!fs.existsSync(logsPath)) fs.mkdirSync(logsPath, { recursive: true })
                // Mirror existing log files into dedicated logs folder
                for (const logName of ['forwarder.log', 'watchdog.log', 'last-incident.json']) {
                  const srcFile = path.join(baseDir, logName)
                  const dstFile = path.join(logsPath, logName)
                  if (fs.existsSync(srcFile) && !fs.existsSync(dstFile)) {
                    try { fs.copyFileSync(srcFile, dstFile) } catch {}
                  } else if (fs.existsSync(srcFile) && fs.existsSync(dstFile)) {
                    try {
                      if (fs.statSync(srcFile).mtimeMs > fs.statSync(dstFile).mtimeMs) {
                        fs.copyFileSync(srcFile, dstFile)
                      }
                    } catch {}
                  }
                }
                if (process.platform === 'win32') {
                  spawn('explorer.exe', [logsPath], { detached: true, stdio: 'ignore' }).unref()
                }
                result = { ok: true, path: logsPath }
              } catch (openErr) {
                result = { ok: false, error: String(openErr?.message || openErr) }
              }
            } else if (action === 'get-route') {
              const freshPolicy = await import(`file:///${path.join(BIN_DIR, 'cloudcode-route-policy.mjs').replace(/\\/g, '/')}?t=${Date.now()}`)
              result = { ok: true, route: freshPolicy.readCloudCodeRoutePreference(), options: freshPolicy.getCloudCodeRouteOptions() }
            } else if (action === 'set-route') {
              const freshPolicy = await import(`file:///${path.join(BIN_DIR, 'cloudcode-route-policy.mjs').replace(/\\/g, '/')}?t=${Date.now()}`)
              result = freshPolicy.writeCloudCodeRoutePreference(url.searchParams.get('route') || 'auto')
            } else if (action === 'get-custom-routes') {
              const freshPolicy = await import(`file:///${path.join(BIN_DIR, 'cloudcode-route-policy.mjs').replace(/\\/g, '/')}?t=${Date.now()}`)
              result = { ok: true, routes: freshPolicy.readCustomRoutes() }
            } else if (action === 'add-custom-route') {
              const freshPolicy = await import(`file:///${path.join(BIN_DIR, 'cloudcode-route-policy.mjs').replace(/\\/g, '/')}?t=${Date.now()}`)
              const name = url.searchParams.get('name') || ''
              const kind = url.searchParams.get('kind') || ''
              const target = url.searchParams.get('target') || ''
              const port = url.searchParams.get('port') || ''
              const bootstrap = url.searchParams.get('bootstrap') || ''
              const added = freshPolicy.addCustomRoute({
                name,
                kind,
                url: (kind === 'resolver' || kind === 'smart-resolver') ? target : undefined,
                host: kind === 'proxy' ? target : undefined,
                port: kind === 'proxy' ? Number(port) : undefined,
                bootstrapIps: bootstrap ? bootstrap.split(',') : [],
              })
              result = { ok: true, route: added, options: freshPolicy.getCloudCodeRouteOptions() }
            } else if (action === 'remove-custom-route') {
              const freshPolicy = await import(`file:///${path.join(BIN_DIR, 'cloudcode-route-policy.mjs').replace(/\\/g, '/')}?t=${Date.now()}`)
              const routeId = url.searchParams.get('id') || ''
              result = freshPolicy.removeCustomRoute(routeId)
              result.options = freshPolicy.getCloudCodeRouteOptions()
            } else if (action === 'test-custom-route') {
              const kind = url.searchParams.get('kind') || 'resolver'
              const target = url.searchParams.get('target') || ''
              const port = Number(url.searchParams.get('port')) || (kind === 'proxy' ? 3066 : 443)
              const bootstrap = url.searchParams.get('bootstrap') || ''
              const t0 = Date.now()

              // 1. Get active token
              let token = ''
              try {
                const authPath = getActiveAuthFile()
                if (authPath && fs.existsSync(authPath)) {
                  token = JSON.parse(fs.readFileSync(authPath, 'utf8')).access_token || ''
                }
              } catch (_) {}

              if (!token) {
                result = { ok: false, latencyMs: Date.now() - t0, error: 'Нет активного токена Google OAuth; авторизуйтесь в виджете' }
              } else {
                let sock = null
                try {
                  if (kind === 'proxy') {
                    sock = await connectViaSocks5Proxy(target || '127.0.0.1', port, 'daily-cloudcode-pa.googleapis.com', 443, 4000)
                  } else {
                    // DoH or Smart DNS
                    let testUrl = target.trim()
                    if (!testUrl.startsWith('https://')) testUrl = 'https://' + testUrl
                    const resolver = {
                      url: testUrl,
                      bootstrapIps: bootstrap ? bootstrap.split(',').map(s => s.trim()).filter(Boolean) : [],
                    }
                    const addresses = await queryDohA(resolver, 'daily-cloudcode-pa.googleapis.com', 3500)
                    if (!addresses || !addresses.length) throw new Error('DoH сервер не вернул IP адресов для Google Cloud Code')
                    let connectedSock = null
                    let lastErr = null
                    for (const addr of addresses.slice(0, 3)) {
                      try {
                        connectedSock = await connectTcpSocket(addr, 443, 2500)
                        break
                      } catch (e) {
                        lastErr = e
                      }
                    }
                    if (!connectedSock) throw lastErr || new Error('Не удалось подключиться к IP адресам, полученным от DoH')
                    sock = connectedSock
                  }

                  // Test real Gemini generation through this custom socket
                  const genRes = await testGeminiGenerationOnSocket(sock, token, 8000)
                  sock = null
                  const latency = Date.now() - t0
                  if (genRes.ok) {
                    result = {
                      ok: true,
                      latencyMs: latency,
                      shortStatus: genRes.shortStatus,
                      status: `✓ Google ответил: генерация успешна (${latency} мс)`,
                      error: null,
                    }
                  } else {
                    const isLocation = genRes.shortStatus === '400 location' || String(genRes.error || '').includes('location')
                    result = {
                      ok: false,
                      latencyMs: latency,
                      shortStatus: genRes.shortStatus,
                      status: isLocation ? '✕ Google отклонил регион: 400 Location not supported' : `✕ Ошибка генерации: ${genRes.shortStatus || 'Недоступно'}`,
                      error: isLocation ? 'Сервер работает, но не подменяет выходной IP для Google API' : (genRes.error || genRes.status),
                    }
                  }
                } catch (netErr) {
                  result = {
                    ok: false,
                    latencyMs: Date.now() - t0,
                    shortStatus: 'Сбой соединения',
                    status: '✕ Не удалось соединиться через этот сервер',
                    error: String(netErr?.message || netErr),
                  }
                } finally {
                  try { sock?.destroy() } catch (_) {}
                }
              }
            } else if (action === 'switch') {
              const email = url.searchParams.get('email') || ''
              result = freshMod ? await freshMod.switchAntigravityAccount(email) : await switchAntigravityAccount(email)
            } else if (action === 'remove-account') {
              const email = url.searchParams.get('email') || ''
              result = freshMod ? await freshMod.removeAntigravityAccount(email) : await removeAntigravityAccount(email)
            } else if (action === 'add-account') {
              result = freshMod ? await freshMod.startAddAntigravityAccount() : await startAddAntigravityAccount()
            } else {
              const restart = action === 'restart'
              result = freshMod ? await freshMod.fetchAntigravityQuota(force || restart, restart) : await fetchAntigravityQuota(force || restart, restart)
            }
            const body = Buffer.from(JSON.stringify(result), 'utf8')
            response.writeHead(200, {
              'content-type': 'application/json; charset=utf-8',
              'cache-control': 'no-store',
              'content-length': body.length,
            })
            response.end(body)
          } catch (err) {
            const services = await ensureAntigravityServices(false).catch(() => null)
            const body = Buffer.from(JSON.stringify({
              ok: false,
              error: String(err?.message || err),
              services,
              accounts: listAccounts(),
            }), 'utf8')
            response.writeHead(200, {
              'content-type': 'application/json; charset=utf-8',
              'cache-control': 'no-store',
              'content-length': body.length,
            })
            response.end(body)
          }
        },
      })
    }
    if (typeof wctx.effect === 'function') wctx.effect(mount, 'antigravity-quota: route')
    else mount()
  })
}
