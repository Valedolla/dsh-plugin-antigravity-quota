window.__ModuleLoader__.load({
  id: 'dsh-plugin-antigravity-quota',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const React = require('react')
    const { useState, useEffect, useRef } = React

    // Shared reactive store for quota data across all mounted instances
    let initialCached = null
    try {
      const saved = localStorage.getItem('antigravity_quota_cache')
      if (saved) initialCached = JSON.parse(saved)
    } catch (_) {}

    const quotaStore = {
      data: initialCached,
      loading: false,
      updatingQuotas: false,
      switchingEmail: null,
      switchFeedback: null,
      oauthProgress: {
        active: false,
        step: 'idle',
        message: '',
        authUrl: null,
        error: null,
      },
      pingTesting: false,
      pingResult: null,
      listeners: new Set(),
      getSnapshot() {
        return {
          data: this.data,
          loading: this.loading,
          updatingQuotas: this.updatingQuotas,
          switchingEmail: this.switchingEmail,
          switchFeedback: this.switchFeedback,
          oauthProgress: this.oauthProgress,
          pingTesting: this.pingTesting,
          pingResult: this.pingResult,
        }
      },
      subscribe(fn) {
        this.listeners.add(fn)
        if (this.data) {
          try { fn(this.getSnapshot(), this.data, this.loading, this.pingTesting, this.pingResult) } catch (_) {}
        }
        return () => this.listeners.delete(fn)
      },
      notify() {
        const snap = this.getSnapshot()
        for (const fn of this.listeners) {
          try { fn(snap, this.data, this.loading, this.pingTesting, this.pingResult) } catch (_) {}
        }
      },
      async testConnection() {
        if (this.pingTesting) return
        this.pingTesting = true
        this.pingResult = null
        this.notify()
        try {
          const res = await fetch('/api/antigravity-quota?action=ping-test')
          const json = await res.json()
          this.pingResult = json
        } catch (err) {
          this.pingResult = { ok: false, error: String(err?.message || err) }
        } finally {
          this.pingTesting = false
          this.notify()
        }
      },
      async fetch(force = false, restart = false) {
        if (this.updatingQuotas && !force && !restart) return
        this.updatingQuotas = true
        if (restart) this.loading = true
        this.notify()
        try {
          const qs = restart ? '?action=restart' : (force ? '?refresh=1' : '')
          const res = await fetch('/api/antigravity-quota' + qs)
          const json = await res.json()
          if (json) {
            if (json.ok) {
              this.data = json
              try { localStorage.setItem('antigravity_quota_cache', JSON.stringify(this.data)) } catch (_) {}
            } else if (json.services) {
              this.data = {
                ...(this.data || {}),
                ok: false,
                error: json.error || 'Ошибка связи',
                services: json.services,
                accounts: json.accounts || this.data?.accounts,
              }
            }
          }
        } catch (err) {
          console.warn('[antigravity-quota] fetch failed:', err)
        } finally {
          this.updatingQuotas = false
          this.loading = false
          this.notify()
        }
      },
      async restartServices() {
        return this.fetch(true, true)
      },
      async switchAccount(email) {
        if (!email || this.switchingEmail) return
        this.switchingEmail = email
        this.switchFeedback = { type: 'switching', message: `Переключение на ${email}...` }
        this.notify()
        try {
          const res = await fetch('/api/antigravity-quota?action=switch&email=' + encodeURIComponent(email))
          const json = await res.json()
          if (json && (json.ok || json.services)) {
            this.data = { ...(this.data || {}), ...json }
            try { localStorage.setItem('antigravity_quota_cache', JSON.stringify(this.data)) } catch (_) {}
            this.switchFeedback = { type: 'success', message: `✓ Аккаунт ${email} активирован` }
            this.notify()
            setTimeout(() => {
              if (this.switchFeedback?.type === 'success') {
                this.switchFeedback = null
                this.notify()
              }
            }, 3000)
          } else {
            this.switchFeedback = { type: 'error', message: json?.error || 'Ошибка переключения аккаунта' }
            this.notify()
          }
        } catch (err) {
          this.switchFeedback = { type: 'error', message: String(err?.message || err) }
          this.notify()
        } finally {
          this.switchingEmail = null
          this.notify()
        }
      },
      async removeAccount(email) {
        if (!email || this.switchingEmail) return
        this.switchFeedback = { type: 'switching', message: `Удаление аккаунта ${email}...` }
        this.notify()
        try {
          const res = await fetch('/api/antigravity-quota?action=remove-account&email=' + encodeURIComponent(email))
          const json = await res.json()
          if (json && (json.ok || json.services)) {
            this.data = { ...(this.data || {}), ...json }
            try { localStorage.setItem('antigravity_quota_cache', JSON.stringify(this.data)) } catch (_) {}
            this.switchFeedback = { type: 'success', message: `✓ Аккаунт ${email} удален` }
            this.notify()
            setTimeout(() => {
              if (this.switchFeedback?.type === 'success') {
                this.switchFeedback = null
                this.notify()
              }
            }, 3000)
          } else {
            this.switchFeedback = { type: 'error', message: json?.error || 'Ошибка удаления аккаунта' }
            this.notify()
          }
        } catch (err) {
          this.switchFeedback = { type: 'error', message: String(err?.message || err) }
          this.notify()
        }
      },
      async addAccount() {
        if (this.oauthProgress.active) return
        this.oauthAborted = false
        this.oauthProgress = {
          active: true,
          step: 'starting',
          message: '🚀 Инициализация безопасной авторизации (PKCE)...',
          authUrl: null,
          error: null,
        }
        this.notify()

        try {
          const startRes = await fetch('/api/antigravity-quota?action=oauth-start', { cache: 'no-store' })
          const startJson = await startRes.json()
          if (!startJson?.ok || !startJson.authUrl || !startJson.state) {
            throw new Error(startJson?.error || 'Не удалось запустить Google OAuth')
          }

          if (this.oauthAborted) {
            try { fetch('/api/antigravity-quota?action=oauth-cancel').catch(() => {}) } catch (_) {}
            return
          }

          this.oauthProgress = {
            active: true,
            step: 'waiting',
            message: '🌐 Браузер открыт. Выберите Google аккаунт для авторизации...',
            authUrl: startJson.authUrl,
            error: null,
          }
          this.notify()

          for (let i = 0; i < 330; i++) {
            if (this.oauthAborted || !this.oauthProgress.active) {
              try { fetch('/api/antigravity-quota?action=oauth-cancel').catch(() => {}) } catch (_) {}
              break
            }

            await new Promise(r => setTimeout(r, 1000))
            if (this.oauthAborted || !this.oauthProgress.active) {
              try { fetch('/api/antigravity-quota?action=oauth-cancel').catch(() => {}) } catch (_) {}
              break
            }

            const statusRes = await fetch(
              '/api/antigravity-quota?action=oauth-status&state=' + encodeURIComponent(startJson.state),
              { cache: 'no-store' }
            )
            const statusJson = await statusRes.json()

            if (this.oauthAborted || !this.oauthProgress.active) break

            if (statusJson?.status === 'received') {
              this.oauthProgress = {
                ...this.oauthProgress,
                step: 'received',
                message: '⚡ Вход в Google выполнен! Код авторизации успешно перехвачен, связываемся с Google API...',
              }
              this.notify()
            } else if (statusJson?.status === 'processing') {
              this.oauthProgress = {
                ...this.oauthProgress,
                step: 'processing',
                message: '🔑 Токены получены! Настройка аккаунта и обновление моста...',
              }
              this.notify()
            } else if (statusJson?.status === 'ok') {
              this.oauthProgress = {
                active: true,
                step: 'ok',
                message: `✅ Аккаунт ${statusJson.email || ''} успешно добавлен и активирован!`,
                authUrl: null,
                error: null,
              }
              this.data = { ...(this.data || {}), ...statusJson }
              try { localStorage.setItem('antigravity_quota_cache', JSON.stringify(this.data)) } catch (_) {}
              this.notify()
              setTimeout(() => {
                this.oauthProgress = { active: false, step: 'idle', message: '', authUrl: null, error: null }
                this.notify()
              }, 3500)
              break
            } else if (statusJson?.status === 'error') {
              throw new Error(statusJson.error || 'Google OAuth завершился ошибкой')
            }
          }
        } catch (err) {
          if (!this.oauthAborted) {
            this.oauthProgress = {
              active: true,
              step: 'error',
              message: '',
              authUrl: this.oauthProgress.authUrl,
              error: String(err?.message || err),
            }
            this.notify()
          }
        }
      },
      closeOAuth() {
        this.oauthAborted = true
        this.oauthProgress = { active: false, step: 'idle', message: '', authUrl: null, error: null }
        this.notify()
        try {
          fetch('/api/antigravity-quota?action=oauth-cancel', { cache: 'no-store' }).catch(() => {})
        } catch (_) {}
      },
    }

    // Start polling every 60s
    let pollTimer = null
    function ensurePolling() {
      if (pollTimer) return
      quotaStore.fetch(false)
      pollTimer = setInterval(() => quotaStore.fetch(false), 60000)
    }

    function formatRemainingTime(resetIso) {
      if (!resetIso) return ''
      const diffMs = Date.parse(resetIso) - Date.now()
      if (isNaN(diffMs) || diffMs <= 0) return 'обновляется сейчас'
      const totalMinutes = Math.max(1, Math.round(diffMs / 60000))
      const days = Math.floor(totalMinutes / (60 * 24))
      const hours = Math.floor((totalMinutes % (60 * 24)) / 60)
      const mins = totalMinutes % 60
      const parts = []
      if (days > 0) parts.push(`${days} дн.`)
      if (hours > 0) parts.push(`${hours} ч.`)
      if (days === 0 && mins > 0) parts.push(`${mins} мин.`)
      return `Полное обновление через ${parts.join(' ')}`
    }

    function ringColor(pct) {
      if (pct >= 45) return '#3b9f51'
      if (pct >= 20) return '#e5a00d'
      return '#ef4444'
    }

    function ProgressRing({ percent, size = 18, stroke = 2.4 }) {
      const p = Math.max(0, Math.min(100, Math.round(percent)))
      const r = (size - stroke) / 2
      const c = 2 * Math.PI * r
      const offset = c - (p / 100) * c
      const color = ringColor(p)
      return React.createElement(
        'svg',
        {
          width: size,
          height: size,
          viewBox: `0 0 ${size} ${size}`,
          style: { flexShrink: 0, transform: 'rotate(-90deg)' },
        },
        React.createElement('circle', {
          cx: size / 2,
          cy: size / 2,
          r,
          fill: 'none',
          stroke: 'rgba(255,255,255,0.13)',
          strokeWidth: stroke,
        }),
        React.createElement('circle', {
          cx: size / 2,
          cy: size / 2,
          r,
          fill: 'none',
          stroke: color,
          strokeWidth: stroke,
          strokeDasharray: `${c} ${c}`,
          strokeDashoffset: offset,
          strokeLinecap: 'round',
          style: { transition: 'stroke-dashoffset 0.35s ease, stroke 0.35s ease' },
        })
      )
    }

    function detectActiveFamilyFromSibling(rootEl) {
      try {
        const parent = rootEl?.parentElement
        if (!parent) return 'gemini'
        let siblingText = ''
        for (const child of parent.children) {
          if (child !== rootEl) {
            siblingText += ' ' + (child.textContent || '')
          }
        }
        const text = siblingText.toLowerCase()
        if (text.includes('claude') || text.includes('gpt') || text.includes('sonnet') || text.includes('opus')) return '3p'
      } catch (_) {}
      return 'gemini'
    }

    function QuotaBadgeWidget() {
      const [snapshot, setSnapshot] = useState(() => quotaStore.getSnapshot())
      const [open, setOpen] = useState(false)
      const [family, setFamily] = useState('gemini')
      const rootRef = useRef(null)
      const [routePreference, setRoutePreference] = useState('auto')
      const [routeOptions, setRouteOptions] = useState([
        { id: 'auto', label: 'Авто (GeoHide US Smart DNS → Comss.one → Router Comss.one → Bezmezhau → WLRUS)' },
        { id: 'karing-proxy', label: 'Karing Full Proxy — SOCKS5 127.0.0.1:3066 (выход через Karing)' },
        { id: 'geohide-us-doh', label: 'GeoHide US Smart DNS — проксирующий DoH, США' },
        { id: 'geohide-88', label: 'GeoHide SNI #1' },
        { id: 'geohide-68', label: 'GeoHide SNI #2' },
        { id: 'geohide-67', label: 'GeoHide SNI #3' },
        { id: 'doh-comss', label: 'Comss.one DNS — DoH-резолвер (не egress-прокси)' },
        { id: 'doh-router-comss', label: 'Router Comss.one — DoH-резолвер (не egress-прокси)' },
        { id: 'doh-bezmezhau', label: 'Bezmezhau DNS — DoH-резолвер (не egress-прокси)' },
        { id: 'doh-wlrus', label: 'WLRUS DNS — DoH-резолвер (не egress-прокси)' },
        { id: 'xbox-1', label: 'Xbox Relay #1' },
        { id: 'xbox-2', label: 'Xbox Relay #2' },
        { id: 'ag-dns', label: 'ag_dns — локальный прокси (только при безопасном gate)' },
      ])
      const [routeSaving, setRouteSaving] = useState(false)
      const [routeSaveError, setRouteSaveError] = useState('')
      const [geminiTestLoading, setGeminiTestLoading] = useState(false)
      const [geminiTestResult, setGeminiTestResult] = useState(null)
      const [geoHideProbeLoading, setGeoHideProbeLoading] = useState(false)
      const [geoHideProbeResult, setGeoHideProbeResult] = useState(null)
      const [geoHideEuProbeLoading, setGeoHideEuProbeLoading] = useState(false)
      const [geoHideEuProbeResult, setGeoHideEuProbeResult] = useState(null)
      useEffect(() => {
        ensurePolling()
        return quotaStore.subscribe((snap) => setSnapshot(snap))
      }, [])
      useEffect(() => {
        let cancelled = false
        fetch('/api/antigravity-quota?action=get-route')
          .then((res) => res.json())
          .then((json) => {
            if (cancelled || !json?.ok) return
            setRoutePreference(json.route || 'auto')
            if (Array.isArray(json.options) && json.options.length) setRouteOptions(json.options)
          })
          .catch(() => {})
        return () => { cancelled = true }
      }, [])
      const changeCloudCodeRoute = async (nextRoute) => {
        setRouteSaving(true)
        setRouteSaveError('')
        setGeminiTestResult(null)
        try {
          const res = await fetch('/api/antigravity-quota?action=set-route&route=' + encodeURIComponent(nextRoute))
          const json = await res.json()
          if (!json?.ok) throw new Error(json?.error || 'Не удалось сохранить маршрут')
          setRoutePreference(json.route || nextRoute)
          // Selecting a route must not fan out into read-only API probes for every route.
          // The user can run the separate connection test explicitly; real generation remains a distinct one-request action.
        } catch (err) {
          setRouteSaveError(String(err?.message || err))
        } finally {
          setRouteSaving(false)
        }
      }
      const runGeoHideUsDohProbe = async () => {
        if (geoHideProbeLoading || geoHideEuProbeLoading) return
        setGeoHideProbeLoading(true)
        setGeoHideProbeResult(null)
        setGeoHideEuProbeResult(null)
        try {
          const res = await fetch('/api/antigravity-quota?action=geohide-us-doh-probe', { cache: 'no-store' })
          const json = await res.json()
          setGeoHideProbeResult(json)
        } catch (err) {
          setGeoHideProbeResult({ ok: false, routeId: 'geohide-us-doh', region: 'US', error: String(err?.message || err), noApiRequestSent: true })
        } finally {
          setGeoHideProbeLoading(false)
        }
      }
      const runGeoHideEuDohProbe = async () => {
        if (geoHideEuProbeLoading || geoHideProbeLoading) return
        setGeoHideEuProbeLoading(true)
        setGeoHideEuProbeResult(null)
        setGeoHideProbeResult(null)
        try {
          const res = await fetch('/api/antigravity-quota?action=geohide-eu-doh-probe', { cache: 'no-store' })
          const json = await res.json()
          setGeoHideEuProbeResult(json)
        } catch (err) {
          setGeoHideEuProbeResult({ ok: false, routeId: 'geohide-eu-doh', region: 'EU', error: String(err?.message || err), noApiRequestSent: true })
        } finally {
          setGeoHideEuProbeLoading(false)
        }
      }

      const runSelectedGeminiTest = async () => {
        if (geminiTestLoading) return
        setGeminiTestLoading(true)
        setGeminiTestResult(null)
        try {
          const res = await fetch('/api/antigravity-quota?action=gemini-test', { cache: 'no-store' })
          const json = await res.json()
          setGeminiTestResult(json)
          try {
            const routeStateResponse = await fetch('/api/antigravity-quota?action=get-route', { cache: 'no-store' })
            const routeState = await routeStateResponse.json()
            if (routeState?.ok && Array.isArray(routeState.options) && routeState.options.length) setRouteOptions(routeState.options)
          } catch (_) {}
        } catch (err) {
          setGeminiTestResult({ ok: false, status: 'Тест не выполнен', error: String(err?.message || err) })
        } finally {
          setGeminiTestLoading(false)
        }
      }


      useEffect(() => {
        ensurePolling()
        if (!quotaStore.data) {
          quotaStore.fetch(true)
        }
        return quotaStore.subscribe((snap) => {
          setSnapshot(snap)
        })
      }, [])

      useEffect(() => {
        const checkFamily = () => {
          if (rootRef.current) {
            setFamily(detectActiveFamilyFromSibling(rootRef.current))
          }
        }
        checkFamily()
        const t = setInterval(checkFamily, 1500)
        return () => clearInterval(t)
      }, [])

      useEffect(() => {
        if (!open) return
        const onDocMouseDown = (e) => {
          if (rootRef.current && !rootRef.current.contains(e.target)) {
            setOpen(false)
          }
        }
        document.addEventListener('mousedown', onDocMouseDown)
        return () => document.removeEventListener('mousedown', onDocMouseDown)
      }, [open])

      const groups = snapshot.data?.groups || []
      const geminiGroup = groups.find(g => (g.displayName || g.label || g.id || '').toLowerCase().includes('gemini')) || groups[0]
      const claudeGroup = groups.find(g => (g.displayName || g.label || g.id || '').toLowerCase().includes('claude')) || groups[1]

      const activeGroup = family === '3p' ? (claudeGroup || geminiGroup) : (geminiGroup || claudeGroup)
      const active5h = activeGroup?.buckets?.find(b => b.window === '5h') || activeGroup?.buckets?.[1] || activeGroup?.buckets?.[0]
      const activeWeekly = activeGroup?.buckets?.find(b => b.window === 'weekly')
      const activePct = active5h
        ? Math.round((active5h.remainingFraction || 0) * 100)
        : (typeof activeGroup?.remainingPercent === 'number' ? activeGroup.remainingPercent : null)
      const weeklyPct = activeWeekly ? Math.round((activeWeekly.remainingFraction || 0) * 100) : null
      const activeEmailShort = (snapshot.data?.activeEmail || snapshot.data?.email || '').split('@')[0]
      const agSrv = snapshot.data?.services?.agDns || { name: 'xbox-failover-bridge', port: 53130, online: true }
      const cliSrv = snapshot.data?.services?.cliProxy || { name: 'cli-proxy-api.exe', port: 8317, online: true }
      const bridgeOnline = snapshot.data?.services?.bridge ? snapshot.data.services.bridge.online : agSrv.online
      const routingDiagnostics = snapshot.data?.services?.routingDiagnostics
      const allServicesOnline = Boolean(agSrv.online && cliSrv.online && bridgeOnline && routingDiagnostics?.filesMatchExpected !== false)
      const bridgeTransport = snapshot.data?.services?.bridge?.lastTransportRoute
      const listenerSummary = (port) => {
        if (!routingDiagnostics?.listenerInspectionSupported) return 'нет данных'
        const found = (routingDiagnostics.listeners || []).filter(listener => Number(listener.port) === port)
        if (!found.length) return 'не слушается'
        return found.map(listener => `${listener.processName || 'процесс'} PID ${listener.pid}${listener.bridgeScript ? ' / bridge' : ''}${listener.cliProxyExe ? ' / cli-proxy-api' : ''}`).join(', ')
      }

      const badgeTitle = activePct !== null
        ? `Google AI Pro (${activeGroup?.displayName || 'Квоты'})\n• 5-часовой лимит: ${activePct}%\n• Недельный лимит: ${weeklyPct !== null ? weeklyPct + '%' : '—'}`
        : 'Лимиты моделей Google AI Pro (Antigravity)'

      return React.createElement(
        'div',
        {
          ref: rootRef,
          style: {
            position: 'relative',
            display: 'inline-flex',
            alignItems: 'center',
            marginRight: '2px',
          },
        },
        React.createElement(
          'button',
          {
            type: 'button',
            title: badgeTitle,
            onClick: (e) => {
              e.stopPropagation()
              const nextOpen = !open
              setOpen(nextOpen)
              if (nextOpen) quotaStore.fetch(true)
            },
            style: {
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              height: '26px',
              padding: '0 8px',
              borderRadius: '6px',
              border: open ? '1px solid rgba(255,255,255,0.22)' : '1px solid rgba(255,255,255,0.08)',
              background: open ? 'rgba(255,255,255,0.09)' : 'rgba(255,255,255,0.04)',
              color: 'rgba(255,255,255,0.88)',
              fontSize: '12px',
              fontWeight: 500,
              cursor: 'pointer',
              userSelect: 'none',
              transition: 'background 0.15s ease, border-color 0.15s ease',
            },
          },
          React.createElement(ProgressRing, {
            percent: activePct !== null ? activePct : 100,
            size: 14,
            stroke: 2.2,
          }),
          React.createElement(
            'span',
            { style: { fontVariantNumeric: 'tabular-nums', lineHeight: 1 } },
            activePct !== null ? `${activePct}%` : '…'
          ),
          activeEmailShort && React.createElement(
            'span',
            {
              style: {
                fontSize: '10.5px',
                color: 'rgba(255,255,255,0.55)',
                maxWidth: '84px',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                lineHeight: 1,
              },
            },
            activeEmailShort
          ),
          React.createElement('span', {
            title: allServicesOnline
              ? 'Единый CONNECT bridge (:53130) и cli-proxy-api.exe (:8317) запущены'
              : 'Внимание: bridge или cli-proxy-api не запущен',
            style: {
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: allServicesOnline ? '#3b9f51' : '#ef4444',
              boxShadow: allServicesOnline ? '0 0 5px rgba(59,159,81,0.8)' : '0 0 6px rgba(239,68,68,0.9)',
              flexShrink: 0,
              marginLeft: '1px',
            },
          })
        ),
        open && React.createElement(
          'div',
          {
            onClick: e => e.stopPropagation(),
            style: {
              position: 'absolute',
              bottom: 'calc(100% + 10px)',
              right: 0,
              width: '400px',
              padding: '16px',
              borderRadius: '12px',
              background: '#18181b',
              border: '1px solid rgba(255,255,255,0.12)',
              boxShadow: '0 16px 40px rgba(0,0,0,0.65)',
              color: '#f4f4f5',
              zIndex: 9999,
              fontFamily: 'system-ui, -apple-system, Segoe UI, sans-serif',
            },
          },
          // Header
          React.createElement(
            'div',
            {
              style: {
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '12px',
              },
            },
            React.createElement(
              'div',
              null,
              React.createElement(
                'div',
                { style: { fontSize: '15px', fontWeight: 600, color: '#ffffff' } },
                'Модели и квоты (Models & Usage)'
              ),
              React.createElement(
                'div',
                { style: { fontSize: '12px', color: 'rgba(255,255,255,0.5)', marginTop: '2px' } },
                `Подписка: Google AI Pro${snapshot.data?.email ? ' · ' + snapshot.data.email : ''}`
              )
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                title: 'Обновить лимиты',
                onClick: () => quotaStore.fetch(true),
                style: {
                  width: '28px',
                  height: '28px',
                  borderRadius: '6px',
                  border: '1px solid rgba(255,255,255,0.1)',
                  background: 'rgba(255,255,255,0.05)',
                  color: '#e4e4e7',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '14px',
                },
              },
              snapshot.updatingQuotas ? '⋯' : '↻'
            )
          ),
          // Account Switcher Bar
          React.createElement(
            'div',
            {
              style: {
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                marginBottom: snapshot.switchFeedback || snapshot.oauthProgress?.active ? '6px' : '12px',
                padding: '8px 10px',
                borderRadius: '8px',
                background: 'rgba(255,255,255,0.035)',
                border: '1px solid rgba(255,255,255,0.08)',
              },
            },
            React.createElement(
              'select',
              {
                value: snapshot.switchingEmail || snapshot.data?.email || (snapshot.data?.accounts?.[0]?.email ?? ''),
                disabled: Boolean(snapshot.switchingEmail || snapshot.oauthProgress?.active),
                onMouseDown: (e) => e.stopPropagation(),
                onChange: (e) => quotaStore.switchAccount(e.target.value),
                style: {
                  flex: 1,
                  height: '26px',
                  borderRadius: '5px',
                  border: snapshot.switchingEmail
                    ? '1px solid rgba(59,130,246,0.6)'
                    : '1px solid rgba(255,255,255,0.14)',
                  background: '#111113',
                  color: '#f4f4f5',
                  fontSize: '11.5px',
                  padding: '0 6px',
                  outline: 'none',
                  cursor: snapshot.switchingEmail ? 'wait' : 'pointer',
                },
              },
              (snapshot.data?.accounts?.length
                ? snapshot.data.accounts
                : (snapshot.data?.email ? [{ email: snapshot.data.email, active: true }] : [])
              ).map((acc) =>
                React.createElement(
                  'option',
                  { key: acc.email, value: acc.email },
                  `${acc.active ? '● ' : ''}${acc.email}`
                )
              )
            ),
            (snapshot.data?.accounts?.length || 0) > 1 && React.createElement(
              'button',
              {
                type: 'button',
                title: `Удалить активный аккаунт (${snapshot.data?.email}) из Harness`,
                disabled: Boolean(snapshot.switchingEmail || snapshot.oauthProgress?.active),
                onMouseDown: (e) => e.stopPropagation(),
                onClick: () => {
                  const target = snapshot.data?.email
                  if (!target) return
                  if (window.confirm(`Удалить Google аккаунт ${target} из Harness?`)) {
                    quotaStore.removeAccount(target)
                  }
                },
                style: {
                  height: '26px',
                  padding: '0 8px',
                  borderRadius: '5px',
                  border: '1px solid rgba(239,68,68,0.35)',
                  background: 'rgba(239,68,68,0.12)',
                  color: '#fca5a5',
                  fontSize: '11px',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                },
              },
              'Удалить'
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                title: 'Авторизовать Google AI Pro через браузер',
                disabled: Boolean(snapshot.switchingEmail || snapshot.oauthProgress?.active),
                onClick: () => quotaStore.addAccount(),
                style: {
                  height: '26px',
                  padding: '0 9px',
                  borderRadius: '5px',
                  border: '1px solid rgba(59,159,81,0.45)',
                  background: 'rgba(59,159,81,0.16)',
                  color: '#86efac',
                  fontSize: '11.5px',
                  fontWeight: 500,
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                },
              },
              snapshot.oauthProgress?.active ? '⋯ Ждём' : '+ Аккаунт'
            )
          ),
          // Instant feedback banner for switching accounts
          snapshot.switchFeedback && React.createElement(
            'div',
            {
              style: {
                marginBottom: '10px',
                padding: '6px 10px',
                borderRadius: '6px',
                fontSize: '11.5px',
                lineHeight: 1.3,
                background: snapshot.switchFeedback.type === 'error'
                  ? 'rgba(239,68,68,0.15)'
                  : snapshot.switchFeedback.type === 'success'
                  ? 'rgba(34,197,94,0.15)'
                  : 'rgba(59,130,246,0.15)',
                border: snapshot.switchFeedback.type === 'error'
                  ? '1px solid rgba(239,68,68,0.3)'
                  : snapshot.switchFeedback.type === 'success'
                  ? '1px solid rgba(34,197,94,0.3)'
                  : '1px solid rgba(59,130,246,0.3)',
                color: snapshot.switchFeedback.type === 'error'
                  ? '#fca5a5'
                  : snapshot.switchFeedback.type === 'success'
                  ? '#86efac'
                  : '#93c5fd',
              },
            },
            snapshot.switchFeedback.message
          ),
          // Interactive progress card for adding an account
          snapshot.oauthProgress?.active && React.createElement(
            'div',
            {
              style: {
                marginBottom: '12px',
                padding: '10px 12px',
                borderRadius: '8px',
                background: 'rgba(59,130,246,0.08)',
                border: '1px solid rgba(59,130,246,0.25)',
                fontSize: '11.5px',
                color: '#e4e4e7',
              },
            },
            React.createElement(
              'div',
              { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' } },
              React.createElement('span', { style: { fontWeight: 600, color: '#93c5fd' } }, 'OAuth Авторизация Google'),
              React.createElement('button', {
                type: 'button',
                onClick: () => quotaStore.closeOAuth(),
                title: 'Отменить авторизацию и закрыть',
                style: {
                  background: 'rgba(255,255,255,0.06)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '4px',
                  color: 'rgba(255,255,255,0.6)',
                  cursor: 'pointer',
                  fontSize: '11px',
                  padding: '1px 6px',
                },
              }, '✕ Отмена')
            ),
            React.createElement('div', { style: { marginTop: '4px', lineHeight: 1.35 } }, snapshot.oauthProgress.message),
            React.createElement(
              'div',
              { style: { display: 'flex', alignItems: 'center', gap: '10px', marginTop: '6px', flexWrap: 'wrap' } },
              snapshot.oauthProgress.authUrl && snapshot.oauthProgress.step !== 'ok' && React.createElement(
                'a',
                {
                  href: snapshot.oauthProgress.authUrl,
                  target: '_blank',
                  rel: 'noreferrer',
                  style: {
                    color: '#60a5fa',
                    textDecoration: 'underline',
                    cursor: 'pointer',
                    fontWeight: 500,
                  },
                },
                'Открыть страницу Google OAuth вручную ↗'
              ),
              snapshot.oauthProgress.step !== 'ok' && React.createElement(
                'button',
                {
                  type: 'button',
                  onClick: () => quotaStore.closeOAuth(),
                  style: {
                    background: 'none',
                    border: 'none',
                    color: '#fca5a5',
                    cursor: 'pointer',
                    fontSize: '11px',
                    textDecoration: 'underline',
                    padding: 0,
                  },
                },
                'Прервать ожидание'
              )
            ),
            snapshot.oauthProgress.error && React.createElement(
              'div',
              { style: { marginTop: '6px', color: '#fca5a5', fontWeight: 500 } },
              `Ошибка: ${snapshot.oauthProgress.error}`
            )
          ),
          // Groups
          ...[
            {
              title: 'Модели Gemini',
              subtitle: 'Gemini 3.8 Flash, Gemini 3.1 Pro',
              group: geminiGroup,
              fallbackPct: snapshot.data?.summary?.primaryPercent ?? 98,
              fallbackReset: snapshot.data?.summary?.resetTime,
            },
            {
              title: 'Модели Claude и GPT',
              subtitle: 'Claude Opus 4.6, Sonnet 4.6, GPT-OSS',
              group: claudeGroup,
              fallbackPct: 100,
              fallbackReset: claudeGroup?.resetTime,
            },
          ].map((sec, idx) => {
            if (!sec.group && sec.fallbackPct === undefined) return null
            const rawBuckets = sec.group?.buckets || (
              typeof sec.group?.remainingPercent === 'number'
                ? [
                    {
                      bucketId: sec.group.id || `group-${idx}`,
                      displayName: sec.group.label || sec.title,
                      window: '5h',
                      remainingFraction: sec.group.remainingPercent / 100,
                      resetTime: sec.group.resetTime || sec.fallbackReset,
                    },
                  ]
                : [
                    {
                      bucketId: `fallback-${idx}`,
                      displayName: sec.title,
                      window: '5h',
                      remainingFraction: (sec.fallbackPct ?? 100) / 100,
                      resetTime: sec.fallbackReset,
                    },
                  ]
            )
            const buckets = [...rawBuckets].sort((a, b) => {
              if (a.window === '5h' && b.window !== '5h') return -1
              if (a.window !== '5h' && b.window === '5h') return 1
              return 0
            })
            return React.createElement(
              'div',
              {
                key: idx,
                style: {
                  marginTop: idx === 0 ? '4px' : '14px',
                },
              },
              React.createElement(
                'div',
                {
                  style: {
                    fontSize: '12.5px',
                    fontWeight: 600,
                    color: '#e4e4e7',
                    marginBottom: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'baseline',
                  },
                },
                React.createElement('span', null, sec.title),
                React.createElement('span', { style: { fontSize: '11px', fontWeight: 400, color: 'rgba(255,255,255,0.42)' } }, sec.subtitle)
              ),
              React.createElement(
                'div',
                {
                  style: {
                    borderRadius: '9px',
                    border: '1px solid rgba(255,255,255,0.08)',
                    background: 'rgba(255,255,255,0.025)',
                    overflow: 'hidden',
                  },
                },
                buckets.map((b, bIdx) => {
                  const hasFraction = typeof b.remainingFraction === 'number'
                  const pct = hasFraction ? Math.round(b.remainingFraction * 100) : null
                  const isWeekly = b.window === 'weekly'
                  const label = isWeekly ? 'Недельный лимит (Weekly Limit)' : 'Лимит на 5 часов (5-Hour Limit)'
                  return React.createElement(
                    'div',
                    {
                      key: b.bucketId || bIdx,
                      style: {
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '10px 12px',
                        borderTop: bIdx > 0 ? '1px solid rgba(255,255,255,0.06)' : 'none',
                      },
                    },
                    React.createElement(
                      'div',
                      { style: { paddingRight: '10px' } },
                      React.createElement(
                        'div',
                        { style: { fontSize: '12.5px', fontWeight: 500, color: '#f4f4f5' } },
                        label
                      ),
                      React.createElement(
                        'div',
                        { style: { fontSize: '11px', color: 'rgba(255,255,255,0.48)', marginTop: '2px' } },
                        formatRemainingTime(b.resetTime)
                      )
                    ),
                    React.createElement(
                      'div',
                      {
                        style: {
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                          flexShrink: 0,
                        },
                      },
                      React.createElement(
                        'span',
                        {
                          style: {
                            fontSize: '13px',
                            fontWeight: 600,
                            fontVariantNumeric: 'tabular-nums',
                            color: '#ffffff',
                          },
                        },
                        pct !== null ? `${pct}%` : '—'
                      ),
                      React.createElement(ProgressRing, {
                        percent: pct !== null ? pct : 0,
                        size: 24,
                        stroke: 2.8,
                      })
                    )
                  )
                })
              )
            )
          }),
          // Services status block
          React.createElement(
            'div',
            {
              style: {
                marginTop: '14px',
                paddingTop: '12px',
                borderTop: '1px solid rgba(255,255,255,0.1)',
              },
            },
            React.createElement(
              'div',
              {
                style: {
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '8px',
                  marginBottom: '10px',
                },
              },
              React.createElement(
                'span',
                { style: { fontSize: '12px', fontWeight: 600, color: '#e4e4e7', whiteSpace: 'nowrap' } },
                'Службы обхода (Bridge)'
              ),
              React.createElement(
                'div',
                { style: { display: 'flex', gap: '6px', alignItems: 'center', flexShrink: 0 } },
                React.createElement(
                  'button',
                  {
                    type: 'button',
                    onClick: () => quotaStore.testConnection(),
                    title: 'Проверить задержку и маршрут до Google API',
                    style: {
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: '4px 8px',
                      borderRadius: '6px',
                      border: '1px solid rgba(255,255,255,0.12)',
                      background: snapshot.pingTesting ? 'rgba(59,130,246,0.18)' : 'rgba(255,255,255,0.05)',
                      color: '#f4f4f5',
                      fontSize: '11px',
                      cursor: 'pointer',
                      whiteSpace: 'nowrap',
                    },
                  },
                  snapshot.pingTesting ? 'Тест…' : '⚡ Тест связи'
                ),
                React.createElement(
                  'button',
                  {
                    type: 'button',
                    onClick: () => quotaStore.restartServices(),
                    title: 'Перезапустить локальные службы моста',
                    style: {
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: '4px 8px',
                      borderRadius: '6px',
                      border: '1px solid rgba(255,255,255,0.12)',
                      background: 'rgba(255,255,255,0.05)',
                      color: '#f4f4f5',
                      fontSize: '11px',
                      cursor: 'pointer',
                      whiteSpace: 'nowrap',
                    },
                  },
                  snapshot.loading ? 'Перезапуск…' : '↻ Перезапуск'
                )
              )
            ),
            React.createElement(
              'div',
              {
                style: {
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '5px',
                  padding: '7px 9px',
                  marginBottom: '8px',
                  borderRadius: '6px',
                  background: 'rgba(255,255,255,0.035)',
                  border: '1px solid rgba(255,255,255,0.08)',
                },
              },
              React.createElement('label', { htmlFor: 'antigravity-cloudcode-route-select', style: { fontSize: '10.5px', color: 'rgba(255,255,255,0.65)' } }, 'Маршрут Google Cloud Code'),
              React.createElement(
                'select',
                {
                  id: 'antigravity-cloudcode-route-select',
                  value: routePreference,
                  disabled: routeSaving,
                  onChange: (event) => changeCloudCodeRoute(event.target.value),
                  title: 'Auto в этой версии использует только Comss.one, Router Comss.one, Bezmezhau и WLRUS DNS. DoH меняет разрешение домена, но не egress-IP. GeoHide, Xbox, Karing и ag_dns доступны только вручную.',
                  style: {
                    width: '100%',
                    minWidth: 0,
                    padding: '6px 8px',
                    borderRadius: '6px',
                    border: '1px solid rgba(255,255,255,0.14)',
                    background: '#242428',
                    color: '#f4f4f5',
                    fontSize: '11px',
                    outline: 'none',
                  },
                },
                routeOptions.map((option) => React.createElement('option', { key: option.id, value: option.id }, option.label))
              ),
              routeSaving ? React.createElement('span', { style: { fontSize: '10px', color: '#93c5fd' } }, 'Сохраняю маршрут…') : null,
              routeSaveError ? React.createElement('span', { style: { fontSize: '10px', color: '#fca5a5' } }, routeSaveError) : null,
              React.createElement('button', {
                type: 'button',
                onClick: runSelectedGeminiTest,
                disabled: geminiTestLoading || routeSaving,
                title: 'Отправляет один короткий реальный запрос Gemini через выбранный маршрут. Может расходовать небольшую часть квоты.',
                style: { alignSelf: 'flex-start', padding: '5px 8px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.13)', background: geminiTestLoading ? 'rgba(59,130,246,0.18)' : 'rgba(255,255,255,0.06)', color: '#f4f4f5', fontSize: '10.5px', cursor: geminiTestLoading || routeSaving ? 'wait' : 'pointer' },
              }, geminiTestLoading ? 'Тест Gemini…' : 'Проверить реальную генерацию (1 запрос)'),
              geminiTestResult ? React.createElement('div', { style: { fontSize: '10.5px', color: geminiTestResult.ok ? '#4ade80' : (geminiTestResult.warning ? '#fbbf24' : '#fca5a5'), whiteSpace: 'normal', overflowWrap: 'anywhere' } },
                `${geminiTestResult.ok ? '✓ ' : '✕ '}${geminiTestResult.shortStatus || geminiTestResult.status || 'Ошибка'}${geminiTestResult.route ? ` · ${geminiTestResult.route}` : ''}${geminiTestResult.latencyMs != null ? ` · ${geminiTestResult.latencyMs} ms` : ''}${geminiTestResult.error ? ` — ${geminiTestResult.error}` : ''}`) : null,
              React.createElement('button', {
                type: 'button',
                onClick: runGeoHideEuDohProbe,
                disabled: geoHideProbeLoading || geoHideEuProbeLoading || geminiTestLoading || routeSaving,
                title: 'Проверяет EU DoH endpoint и TLS/SNI по IP из списка администратора. Не вызывает Google API и не расходует квоту.',
                style: { alignSelf: 'flex-start', padding: '5px 8px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.13)', background: geoHideEuProbeLoading ? 'rgba(59,130,246,0.18)' : 'rgba(255,255,255,0.06)', color: '#f4f4f5', fontSize: '10.5px', cursor: geoHideEuProbeLoading || geoHideProbeLoading || geminiTestLoading || routeSaving ? 'wait' : 'pointer' },
              }, geoHideEuProbeLoading ? 'Проверка GeoHide EU DNS…' : 'Проверить GeoHide EU DNS (без генерации)'),
              geoHideEuProbeResult ? React.createElement('div', { style: { fontSize: '10.5px', color: geoHideEuProbeResult.smartProxyDetected && geoHideEuProbeResult.tlsOk ? '#4ade80' : (geoHideEuProbeResult.dnsAvailable ? '#fbbf24' : '#fca5a5'), whiteSpace: 'normal', overflowWrap: 'anywhere' } },
                `[GeoHide EU Smart DNS · ${geoHideEuProbeResult.endpoint || 'https://eu.geohide.ru/dns-query'} · Регион: ${geoHideEuProbeResult.region || 'EU'}] ${geoHideEuProbeResult.ok ? 'Проверка DNS: ' : 'Ошибка проверки: '}${geoHideEuProbeResult.assessment || geoHideEuProbeResult.error || 'нет результата'}${geoHideEuProbeResult.results?.length ? ' · ' + geoHideEuProbeResult.results.map((item) => `${item.dnsServer}: ${item.ok ? item.addresses.join(', ') : item.error || 'недоступен'}`).join(' | ') : ''}${geoHideEuProbeResult.tlsChecks?.length ? ' · TLS/SNI: ' + geoHideEuProbeResult.tlsChecks.map((item) => `${item.address} ${item.ok ? 'OK' : 'ошибка'}`).join(', ') : ''}`) : null,
              React.createElement('button', {
                type: 'button',
                onClick: runGeoHideUsDohProbe,
                disabled: geoHideProbeLoading || geoHideEuProbeLoading || geminiTestLoading || routeSaving,
                title: 'Проверяет только DNS-ответ GeoHide US и TLS/SNI к известному адресу GeoHide. Не вызывает Google API и не расходует квоту.',
                style: { alignSelf: 'flex-start', padding: '5px 8px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.13)', background: geoHideProbeLoading ? 'rgba(59,130,246,0.18)' : 'rgba(255,255,255,0.06)', color: '#f4f4f5', fontSize: '10.5px', cursor: geoHideProbeLoading || geoHideEuProbeLoading || geminiTestLoading || routeSaving ? 'wait' : 'pointer' },
              }, geoHideProbeLoading ? 'Проверка GeoHide US DNS…' : 'Проверить GeoHide US DNS (без генерации)'),
              geoHideProbeResult ? React.createElement('div', { style: { fontSize: '10.5px', color: geoHideProbeResult.smartProxyDetected && geoHideProbeResult.tlsOk ? '#4ade80' : (geoHideProbeResult.dnsAvailable ? '#fbbf24' : '#fca5a5'), whiteSpace: 'normal', overflowWrap: 'anywhere' } },
                `[GeoHide US Smart DNS · ${geoHideProbeResult.endpoint || 'https://us.geohide.ru/dns-query'} · Регион: ${geoHideProbeResult.region || 'US'}] ${geoHideProbeResult.ok ? 'Проверка DNS: ' : 'Ошибка проверки: '}${geoHideProbeResult.assessment || geoHideProbeResult.error || 'нет результата'}${geoHideProbeResult.results?.length ? ' · ' + geoHideProbeResult.results.map((item) => `${item.dnsServer}: ${item.ok ? item.addresses.join(', ') : item.error || 'недоступен'}`).join(' | ') : ''}${geoHideProbeResult.tlsChecks?.length ? ' · TLS/SNI: ' + geoHideProbeResult.tlsChecks.map((item) => `${item.address} ${item.ok ? 'OK' : 'ошибка'}`).join(', ') : ''}`) : null
            ),
            React.createElement(
              'div',
              {
                style: {
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '5px 9px',
                  marginBottom: '8px',
                  borderRadius: '6px',
                  background: 'rgba(59,159,81,0.08)',
                  border: '1px solid rgba(59,159,81,0.22)',
                  fontSize: '11px',
                },
              },
              React.createElement(
                'div',
                { style: { display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' } },
                React.createElement('span', {
                  style: {
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: '#3b9f51',
                    boxShadow: '0 0 6px #3b9f51',
                    flexShrink: 0,
                  },
                }),
                React.createElement('span', { style: { color: 'rgba(255,255,255,0.6)', flexShrink: 0 } }, 'Активный маршрут:'),
                React.createElement(
                  'span',
                  {
                    style: {
                      fontWeight: 600,
                      color: '#4ade80',
                      textOverflow: 'ellipsis',
                      overflow: 'hidden',
                      whiteSpace: 'nowrap',
                    },
                  },
                  snapshot.data?.services?.activeRoute || snapshot.pingResult?.activeRoute || 'Нет подтверждённого Cloud Code туннеля'
                )
              ),
              React.createElement('span', { style: { fontSize: '10px', color: 'rgba(255,255,255,0.4)', flexShrink: 0 } }, ':53130')
            ),
            bridgeTransport?.kind === 'resolver' && React.createElement(
              'div',
              { style: { marginTop: '6px', marginBottom: '6px', padding: '7px 9px', borderRadius: '6px', background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.24)', color: '#fbbf24', fontSize: '10.5px', lineHeight: '1.4' } },
              'DoH меняет только DNS-резолвинг, но не egress-IP. Ответ 400 о неподдерживаемом регионе этим маршрутом не считается исправленным; проверяй маршрут с relay/поддерживаемым выходом.'
            ),
            bridgeTransport?.kind === 'smart-resolver' && React.createElement(
              'div',
              { style: { marginTop: '6px', marginBottom: '6px', padding: '7px 9px', borderRadius: '6px', background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.24)', color: '#93c5fd', fontSize: '10.5px', lineHeight: '1.4' } },
              'GeoHide US Smart DNS может возвращать адрес прокси для поддерживаемых доменов. Нажми отдельную проверку DNS без генерации; результат ещё не гарантирует, что Google примет аккаунт или API-запрос.'
            ),
            React.createElement(
              'div',
              {
                style: {
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr',
                  gap: '8px',
                },
              },
              [
                snapshot.data?.services?.agDns || { name: 'xbox-failover-bridge', port: 53130, online: true },
                snapshot.data?.services?.cliProxy || { name: 'cli-proxy-api.exe', port: 8317, online: true },
              ].map((srv, sIdx) =>
                React.createElement(
                  'div',
                  {
                    key: sIdx,
                    style: {
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '6px 9px',
                      borderRadius: '7px',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.07)',
                      fontSize: '11.5px',
                    },
                  },
                  React.createElement(
                    'div',
                    { style: { display: 'flex', alignItems: 'center', gap: '6px' } },
                    React.createElement('span', {
                      style: {
                        width: '7px',
                        height: '7px',
                        borderRadius: '50%',
                        background: srv.online ? '#3b9f51' : '#ef4444',
                        boxShadow: srv.online ? '0 0 6px #3b9f51' : '0 0 6px #ef4444',
                        display: 'inline-block',
                      },
                    }),
                    React.createElement('span', { style: { fontWeight: 500, color: '#f4f4f5' } }, srv.name)
                  ),
                  React.createElement('span', { style: { color: 'rgba(255,255,255,0.45)', fontVariantNumeric: 'tabular-nums' } }, `:${srv.port}`)
                )
              )
            ),
            routingDiagnostics && React.createElement(
              'div',
              { style: { marginTop: '8px', padding: '8px 9px', borderRadius: '7px', background: routingDiagnostics.filesMatchExpected ? 'rgba(59,159,81,0.06)' : 'rgba(239,68,68,0.08)', border: `1px solid ${routingDiagnostics.filesMatchExpected ? 'rgba(59,159,81,0.2)' : 'rgba(239,68,68,0.25)'}`, fontSize: '10px', lineHeight: '1.45', overflowWrap: 'anywhere' } },
              React.createElement('div', { style: { fontWeight: 600, color: routingDiagnostics.filesMatchExpected ? '#86efac' : '#fca5a5', marginBottom: '3px' } }, `proxy_url в файлах: ${routingDiagnostics.filesMatchExpected ? 'совпадает с 53130' : 'расхождение или отсутствует'}`),
              React.createElement('div', { style: { color: 'rgba(255,255,255,0.7)' } }, `config.yaml: ${routingDiagnostics.configYamlProxyUrl || 'не найден'} · активный auth: ${routingDiagnostics.activeAuthProxyUrl || 'не задан'}`),
              React.createElement('div', { style: { color: 'rgba(255,255,255,0.62)', marginTop: '3px' } }, `Listener 53130: ${listenerSummary(53130)}`),
              React.createElement('div', { style: { color: 'rgba(255,255,255,0.62)' } }, `Listener 53129: ${listenerSummary(53129)} · 8317: ${listenerSummary(8317)}`),
              React.createElement('div', { style: { color: routingDiagnostics.cliRestartVerified === false || routingDiagnostics.cliProcessStartedAfterConfig === false ? '#fca5a5' : 'rgba(255,255,255,0.5)', marginTop: '3px' } }, routingDiagnostics.cliRestartVerified === false || routingDiagnostics.cliProcessStartedAfterConfig === false ? 'cli-proxy-api: загрузка текущего config.yaml не подтверждена.' : routingDiagnostics.cliProcessStartedAfterConfig === true ? 'cli-proxy-api запущен после последнего изменения config.yaml.' : routingDiagnostics.listenerInspectionSupported ? 'Владельцы портов проверены через Windows.' : 'Владельцы портов не удалось проверить в этой среде.')
            ),
            snapshot.pingResult && React.createElement(
              'div',
              {
                style: {
                  marginTop: '8px',
                  padding: '8px 10px',
                  borderRadius: '7px',
                  background: snapshot.pingResult.ok ? 'rgba(59,159,81,0.08)' : 'rgba(239,68,68,0.08)',
                  border: `1px solid ${snapshot.pingResult.ok ? 'rgba(59,159,81,0.25)' : 'rgba(239,68,68,0.25)'}`,
                  fontSize: '11px',
                  lineHeight: '1.4',
                },
              },
              React.createElement(
                'div',
                { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3px' } },
                React.createElement(
                  'span',
                  { style: { fontWeight: 600, color: snapshot.pingResult.ok ? '#4ade80' : '#f87171' } },
                  snapshot.pingResult.ok ? '✓ fetchAvailableModels: 200 OK (это не проверка генерации)' : '✕ Ошибка доступа к Google API'
                ),
                React.createElement(
                  'span',
                  { style: { color: 'rgba(255,255,255,0.5)', fontVariantNumeric: 'tabular-nums', fontSize: '10.5px' } },
                  `${snapshot.pingResult.checks?.googleApi?.latencyMs || snapshot.pingResult.totalLatencyMs || 0} мс`
                )
              ),
              React.createElement(
                'div',
                { style: { color: 'rgba(255,255,255,0.7)', fontSize: '10.5px', marginBottom: '4px' } },
                `Статус: ${snapshot.pingResult.checks?.googleApi?.status || (snapshot.pingResult.ok ? '200 OK' : 'Ошибка')} · Релей: ${snapshot.pingResult.activeRoute || 'auto'}`
              ),
              !snapshot.pingResult.ok && snapshot.pingResult.checks?.googleApi?.error && React.createElement(
                'div',
                { style: { marginTop: '2px', marginBottom: '6px', color: '#fca5a5', fontSize: '10.5px', fontWeight: 500 } },
                `Причина: ${snapshot.pingResult.checks.googleApi.error}`
              ),
              snapshot.data?.services?.bridge?.lastApiResult && React.createElement(
                'div',
                { style: { marginTop: '4px', color: snapshot.data.services.bridge.lastApiResult.ok ? '#4ade80' : '#fca5a5', fontSize: '10.5px' } },
                `Последняя проверка API: ${snapshot.data.services.bridge.lastApiResult.ok ? 'успешно' : 'ошибка'} · ${snapshot.data.services.bridge.lastApiResult.stage} · ${snapshot.data.services.bridge.lastApiResult.shortStatus} · маршрут: ${snapshot.data.services.bridge.lastApiResult.routeLabel || snapshot.data.services.bridge.lastApiResult.routeId || 'не подтверждён'}`
              ),
              snapshot.pingResult.routes && React.createElement(
                'div',
                { style: { marginTop: '6px', paddingTop: '6px', borderTop: '1px solid rgba(255,255,255,0.08)' } },
                React.createElement(
                  'div',
                  { style: { fontSize: '10px', color: 'rgba(255,255,255,0.5)', marginBottom: '4px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px' } },
                  'Все маршруты обхода:'
                ),
                React.createElement(
                  'div',
                  { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px', maxHeight: '240px', overflowY: 'auto', paddingRight: '2px' } },
                  snapshot.pingResult.routes.map((r, rIdx) => {
                    const activeLabel = String(snapshot.pingResult.activeRoute || '')
                    const isActive = activeLabel.includes(r.host) || activeLabel.toLowerCase().includes(String(r.name || '').replace(' (DoH)', '').toLowerCase()) || activeLabel.toLowerCase().includes(String(r.id || '').toLowerCase())
                    return React.createElement(
                      'div',
                      {
                        key: rIdx,
                        title: [r.status, r.error, r.dnsAddresses?.length ? `DNS A: ${r.dnsAddresses.join(', ')}` : ''].filter(Boolean).join(' · '),
                        style: {
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '3px 6px',
                          borderRadius: '4px',
                          background: isActive ? 'rgba(59,159,81,0.12)' : 'rgba(255,255,255,0.03)',
                          border: isActive ? '1px solid rgba(59,159,81,0.25)' : '1px solid rgba(255,255,255,0.05)',
                          fontSize: '10px',
                        },
                      },
                      React.createElement(
                        'div',
                        { style: { display: 'flex', alignItems: 'center', gap: '4px', overflow: 'hidden' } },
                        React.createElement('span', {
                          style: {
                            width: '5px',
                            height: '5px',
                            borderRadius: '50%',
                            background: r.ok ? '#3b9f51' : (r.warning ? '#e5a00d' : '#ef4444'),
                            flexShrink: 0,
                          },
                        }),
                        React.createElement(
                          'span',
                          { style: { color: isActive ? '#4ade80' : '#e4e4e7', fontWeight: isActive ? 600 : 400, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' } },
                          r.name
                        )
                      ),
                      React.createElement(
                        'span',
                        { style: { color: r.ok ? 'rgba(255,255,255,0.65)' : (r.warning ? '#e5a00d' : '#fca5a5'), fontVariantNumeric: 'tabular-nums', flexShrink: 0, marginLeft: '4px' } },
                        r.shortStatus || (r.ok ? `${r.latencyMs} мс` : 'Ошибка')
                      )
                    )
                  })
                )
              )
            )
          )
        )
      )
    }

    function AntigravityPluginSettingsCard(props) {
      const pluginId = props?.plugin?.id || props?.item?.id || props?.id || 'dsh-plugin-antigravity-quota'
      if (
        props?.plugin &&
        pluginId !== 'dsh-plugin-antigravity-quota' &&
        !String(pluginId).includes('antigravity-quota')
      ) {
        return null
      }

      const [snapshot, setSnapshot] = useState(() => quotaStore.getSnapshot())
      const accounts = snapshot.data?.accounts || []
      const activeEmail = snapshot.data?.activeEmail || snapshot.data?.email || 'Неизвестен'
      const groups = snapshot.data?.groups || []
      const services = snapshot.data?.services || {}

      return React.createElement(
        'div',
        {
          style: {
            marginTop: '10px',
            marginBottom: '6px',
            padding: '12px 14px',
            borderRadius: '10px',
            background: 'rgba(24, 24, 28, 0.85)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            color: '#f4f4f5',
            fontSize: '12.5px',
          },
        },
        React.createElement(
          'div',
          {
            style: {
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '8px',
              marginBottom: '10px',
              flexWrap: 'wrap',
            },
          },
          React.createElement(
            'div',
            { style: { display: 'flex', alignItems: 'center', gap: '8px' } },
            React.createElement('span', {
              style: {
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: snapshot.data?.ok ? '#3b9f51' : '#ef4444',
                boxShadow: snapshot.data?.ok ? '0 0 6px #3b9f51' : '0 0 6px #ef4444',
              },
            }),
            React.createElement(
              'span',
              { style: { fontWeight: 600, fontSize: '13px' } },
              'Управление аккаунтами Google AI Pro и мостом'
            ),
            React.createElement(
              'span',
              { style: { fontSize: '11.5px', color: 'rgba(255,255,255,0.5)' } },
              `(${activeEmail})`
            )
          ),
          React.createElement(
            'div',
            { style: { display: 'flex', alignItems: 'center', gap: '6px' } },
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () => quotaStore.addAccount(),
                disabled: Boolean(snapshot.switchingEmail || snapshot.oauthProgress?.active),
                style: {
                  padding: '4px 9px',
                  borderRadius: '6px',
                  border: '1px solid rgba(59, 159, 81, 0.45)',
                  background: 'rgba(59, 159, 81, 0.16)',
                  color: '#86efac',
                  fontSize: '11.5px',
                  fontWeight: 500,
                  cursor: 'pointer',
                },
              },
              snapshot.oauthProgress?.active ? '⋯ Ждём OAuth' : '+ Добавить Google аккаунт'
            ),
            React.createElement(
              'button',
              {
                type: 'button',
                onClick: () => quotaStore.restartServices(),
                disabled: Boolean(snapshot.switchingEmail || snapshot.oauthProgress?.active),
                style: {
                  padding: '4px 9px',
                  borderRadius: '6px',
                  border: '1px solid rgba(255,255,255,0.14)',
                  background: 'rgba(255,255,255,0.06)',
                  color: '#e4e4e7',
                  fontSize: '11.5px',
                  cursor: 'pointer',
                },
              },
              snapshot.loading ? 'Обновление…' : '↻ Перезапустить мост'
            )
          )
        ),
        snapshot.switchFeedback && React.createElement(
          'div',
          {
            style: {
              marginBottom: '10px',
              padding: '6px 10px',
              borderRadius: '6px',
              fontSize: '11.5px',
              background: snapshot.switchFeedback.type === 'error'
                ? 'rgba(239,68,68,0.15)'
                : snapshot.switchFeedback.type === 'success'
                ? 'rgba(34,197,94,0.15)'
                : 'rgba(59,130,246,0.15)',
              border: snapshot.switchFeedback.type === 'error'
                ? '1px solid rgba(239,68,68,0.3)'
                : snapshot.switchFeedback.type === 'success'
                ? '1px solid rgba(34,197,94,0.3)'
                : '1px solid rgba(59,130,246,0.3)',
              color: snapshot.switchFeedback.type === 'error'
                ? '#fca5a5'
                : snapshot.switchFeedback.type === 'success'
                ? '#86efac'
                : '#93c5fd',
            },
          },
          snapshot.switchFeedback.message
        ),
        snapshot.oauthProgress?.active && React.createElement(
          'div',
          {
            style: {
              marginBottom: '12px',
              padding: '10px 12px',
              borderRadius: '8px',
              background: 'rgba(59,130,246,0.08)',
              border: '1px solid rgba(59,130,246,0.25)',
              fontSize: '11.5px',
              color: '#e4e4e7',
            },
          },
          React.createElement(
            'div',
            { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' } },
            React.createElement('span', { style: { fontWeight: 600, color: '#93c5fd' } }, 'OAuth Авторизация Google'),
            React.createElement('button', {
              type: 'button',
              onClick: () => quotaStore.closeOAuth(),
              style: {
                background: 'rgba(255,255,255,0.06)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '4px',
                color: 'rgba(255,255,255,0.6)',
                cursor: 'pointer',
                fontSize: '11px',
                padding: '1px 6px',
              },
            }, '✕ Отмена')
          ),
          React.createElement('div', { style: { marginTop: '4px', lineHeight: 1.35 } }, snapshot.oauthProgress.message),
          React.createElement(
            'div',
            { style: { display: 'flex', alignItems: 'center', gap: '10px', marginTop: '6px', flexWrap: 'wrap' } },
            snapshot.oauthProgress.authUrl && snapshot.oauthProgress.step !== 'ok' && React.createElement(
              'a',
              {
                href: snapshot.oauthProgress.authUrl,
                target: '_blank',
                rel: 'noreferrer',
                style: { color: '#60a5fa', textDecoration: 'underline', cursor: 'pointer', fontWeight: 500 },
              },
              'Открыть страницу Google OAuth вручную ↗'
            ),
            snapshot.oauthProgress.step !== 'ok' && React.createElement(
              'button',
              {
                type: 'button',
                onClick: () => quotaStore.closeOAuth(),
                style: {
                  background: 'none',
                  border: 'none',
                  color: '#fca5a5',
                  cursor: 'pointer',
                  fontSize: '11px',
                  textDecoration: 'underline',
                  padding: 0,
                },
              },
              'Прервать ожидание'
            )
          ),
          snapshot.oauthProgress.error && React.createElement(
            'div',
            { style: { marginTop: '6px', color: '#fca5a5', fontWeight: 500 } },
            `Ошибка: ${snapshot.oauthProgress.error}`
          )
        ),
        React.createElement(
          'div',
          {
            style: {
              display: 'flex',
              flexWrap: 'wrap',
              gap: '6px',
              marginBottom: groups.length > 0 ? '10px' : '4px',
            },
          },
          accounts.map((acc) =>
            React.createElement(
              'div',
              {
                key: acc.email,
                style: {
                  display: 'inline-flex',
                  alignItems: 'center',
                  borderRadius: '7px',
                  border: acc.active
                    ? '1px solid rgba(59, 130, 246, 0.6)'
                    : snapshot.switchingEmail === acc.email
                    ? '1px solid rgba(245, 158, 11, 0.6)'
                    : '1px solid rgba(255, 255, 255, 0.1)',
                  background: acc.active
                    ? 'rgba(59, 130, 246, 0.18)'
                    : snapshot.switchingEmail === acc.email
                    ? 'rgba(245, 158, 11, 0.18)'
                    : 'rgba(255, 255, 255, 0.04)',
                },
              },
              React.createElement(
                'button',
                {
                  type: 'button',
                  onClick: () => {
                    if (!acc.active && !snapshot.switchingEmail) {
                      quotaStore.switchAccount(acc.email)
                    }
                  },
                  style: {
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '5px 8px 5px 10px',
                    background: 'none',
                    border: 'none',
                    color: acc.active ? '#93c5fd' : snapshot.switchingEmail === acc.email ? '#fde68a' : '#d4d4d8',
                    fontSize: '12px',
                    fontWeight: acc.active ? 600 : 400,
                    cursor: acc.active || snapshot.switchingEmail ? 'default' : 'pointer',
                  },
                },
                React.createElement('span', {
                  style: {
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: acc.active
                      ? '#60a5fa'
                      : snapshot.switchingEmail === acc.email
                      ? '#f59e0b'
                      : 'rgba(255,255,255,0.3)',
                  },
                }),
                acc.email,
                acc.active ? ' (Активен)' : snapshot.switchingEmail === acc.email ? ' (Переключение…)' : ''
              ),
              accounts.length > 1 && React.createElement(
                'button',
                {
                  type: 'button',
                  title: `Удалить ${acc.email}`,
                  disabled: Boolean(snapshot.switchingEmail || snapshot.oauthProgress?.active),
                  onClick: (e) => {
                    e.stopPropagation()
                    if (window.confirm(`Удалить Google аккаунт ${acc.email} из Harness?`)) {
                      quotaStore.removeAccount(acc.email)
                    }
                  },
                  style: {
                    padding: '4px 8px',
                    background: 'none',
                    border: 'none',
                    borderLeft: '1px solid rgba(255,255,255,0.08)',
                    color: 'rgba(255,255,255,0.4)',
                    fontSize: '11px',
                    cursor: 'pointer',
                    lineHeight: 1,
                  },
                  onMouseEnter: (e) => { e.currentTarget.style.color = '#ef4444' },
                  onMouseLeave: (e) => { e.currentTarget.style.color = 'rgba(255,255,255,0.4)' },
                },
                '✕'
              )
            )
          )
        ),
        groups.length > 0 &&
          React.createElement(
            'div',
            {
              style: {
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                gap: '8px',
              },
            },
            groups.map((grp) => {
              const b5h = grp.buckets?.find(b => b.window === '5h')
              const bWeekly = grp.buckets?.find(b => b.window === 'weekly')
              const p5h = b5h ? Math.round(b5h.remainingFraction * 100) : (grp.remainingPercent ?? 100)
              const pW = bWeekly ? Math.round(bWeekly.remainingFraction * 100) : null
              const label = grp.displayName || grp.label || grp.id
              const displayVal = pW !== null ? `5ч: ${p5h}% · Нед: ${pW}%` : `${p5h}%`
              return React.createElement(
                'div',
                {
                  key: grp.id || label,
                  style: {
                    padding: '6px 9px',
                    borderRadius: '7px',
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid rgba(255,255,255,0.07)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '11.5px',
                  },
                },
                React.createElement('span', { style: { color: '#d4d4d8' } }, label),
                React.createElement(
                  'span',
                  {
                    style: {
                      fontWeight: 700,
                      color: ringColor(p5h),
                    },
                  },
                  displayVal
                )
              )
            })
          ),
        services?.cliProxy?.upstream &&
          React.createElement(
            'div',
            {
              style: {
                marginTop: '8px',
                fontSize: '11px',
                color: 'rgba(255,255,255,0.45)',
              },
            },
            `Активный маршрут: ${services.activeRoute || services.cliProxy.upstream} | ${formatRemainingTime(snapshot.data?.summary?.resetTime)}`
          )
      )
    }

    const inject = ['slots']

    function apply(ctx) {
      ctx.slots.inject('conversation.input.right', () =>
        ctx.slots.register(
          {
            name: 'conversation.input.right',
            id: 'antigravity-quota-widget',
            order: 100,
          },
          QuotaBadgeWidget
        )
      )

      ctx.slots.inject('plugins.bundle.config', () =>
        ctx.slots.register(
          {
            name: 'plugins.bundle.config',
            key: 'dsh-plugin-antigravity-quota',
          },
          AntigravityPluginSettingsCard
        )
      )
    }

    exports.inject = inject
    exports.apply = apply
    return module.exports
  },
})
