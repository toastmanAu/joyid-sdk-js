/**
 * embedded.ts — JoyID auth flow for embedded/IoT devices
 *
 * Standard JoyID uses popup or redirect — both require a browser on the
 * requesting device. This module adds a polling-based flow designed for
 * headless or display-only devices (ESP32, WyVault, kiosks, etc.):
 *
 *   1. Device generates a session ID + builds a JoyID auth URL
 *   2. Device displays the URL as a QR code
 *   3. User scans → authenticates on phone → JoyID redirects to callback Worker
 *   4. Cloudflare Worker stores the signed credential keyed by session ID
 *   5. Device polls the Worker until credential arrives (or timeout)
 *   6. Device verifies P-256/secp256r1 signature locally (mbedTLS on ESP32)
 *
 * Architecture:
 *
 *   ESP32 / WyVault
 *       │  displays QR
 *       │  polls GET /session/<id>
 *       ▼
 *   Cloudflare Worker  (wyltek-joyid-auth.workers.dev)
 *       │  receives redirect from JoyID
 *       │  stores credential in KV
 *       ▼
 *   JoyID app (app.joyid.dev)
 *       │  authenticates via passkey/WebAuthn
 *       │  redirects → callback URL with _data_
 *       ▼
 *   User's phone
 */

import { buildJoyIDURL } from './url'
import type { AuthRequest, AuthResponseData } from '../types/dapp'
import { encodeSearch, decodeSearch } from '../utils'

// ── Types ────────────────────────────────────────────────────────────────────

export interface EmbeddedAuthConfig {
  /** Base URL of the Cloudflare Worker callback receiver */
  workerURL: string
  /** How often to poll for the credential (ms). Default: 2000 */
  pollIntervalMs?: number
  /** Total time to wait before giving up (ms). Default: 300000 (5 min) */
  timeoutMs?: number
  /** Called each poll cycle — use to update a UI countdown or spinner */
  onPoll?: (elapsedMs: number, sessionId: string) => void
}

export interface EmbeddedAuthSession {
  /** Unique session ID — embed in QR code URL */
  sessionId: string
  /** Full JoyID auth URL to display as QR code */
  qrURL: string
  /** Promise that resolves when user completes auth */
  promise: Promise<AuthResponseData>
  /** Call this to cancel polling early */
  cancel: () => void
}

export interface EmbeddedCredential {
  /** CKB address derived from the passkey public key */
  address: string
  /** Hex-encoded secp256r1 (P-256) public key */
  pubkey: string
  /** Key type: 'main' | 'sub' */
  keyType: string
  /** Raw auth response from JoyID */
  raw: AuthResponseData
}

// ── Session ID ───────────────────────────────────────────────────────────────

const generateSessionId = (): string => {
  const bytes = new Uint8Array(16)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes)
  } else {
    // Node.js fallback (for testing)
    const { randomBytes } = require('crypto') // eslint-disable-line @typescript-eslint/no-var-requires
    const buf = randomBytes(16)
    bytes.set(buf)
  }
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ── Core: authWithPolling ────────────────────────────────────────────────────

/**
 * Start an embedded auth session.
 *
 * @example
 * const session = authWithPolling(
 *   { redirectURL: 'unused', title: 'WyVault' },
 *   { workerURL: 'https://wyltek-joyid-auth.workers.dev' }
 * )
 * displayQRCode(session.qrURL)
 * const credential = await session.promise
 * verifyP256Signature(credential.pubkey, credential.raw.signature)
 */
export const authWithPolling = (
  request: Omit<AuthRequest, 'redirectURL'>,
  config: EmbeddedAuthConfig
): EmbeddedAuthSession => {
  const sessionId = generateSessionId()
  const workerURL = config.workerURL.replace(/\/$/, '')
  const pollInterval = config.pollIntervalMs ?? 2000
  const timeout = config.timeoutMs ?? 300_000

  // The redirectURL points to our Worker callback — includes session ID
  const callbackURL = `${workerURL}/callback?session=${sessionId}`

  const fullRequest: AuthRequest = {
    ...request,
    redirectURL: callbackURL,
  }

  const qrURL = buildJoyIDURL(fullRequest, 'redirect', '/auth')

  let cancelled = false
  let intervalId: ReturnType<typeof setInterval> | null = null

  const promise = new Promise<AuthResponseData>((resolve, reject) => {
    const startTime = Date.now()

    const poll = async () => {
      if (cancelled) {
        reject(new Error('EmbeddedAuth: cancelled'))
        return
      }

      const elapsed = Date.now() - startTime
      if (elapsed > timeout) {
        clearInterval(intervalId!)
        reject(new Error(`EmbeddedAuth: timed out after ${timeout}ms`))
        return
      }

      config.onPoll?.(elapsed, sessionId)

      try {
        const res = await fetch(`${workerURL}/session/${sessionId}`)
        if (res.status === 200) {
          clearInterval(intervalId!)
          const data = await res.json() as AuthResponseData
          resolve(data)
        }
        // 404 = not yet — keep polling
      } catch (_) {
        // Network blip — keep polling
      }
    }

    intervalId = setInterval(poll, pollInterval)
    // First poll immediately
    poll()
  })

  return {
    sessionId,
    qrURL,
    promise,
    cancel: () => {
      cancelled = true
      if (intervalId) clearInterval(intervalId)
    },
  }
}

// ── Cloudflare Worker source ─────────────────────────────────────────────────
// See: packages/common/src/sdk/embedded-worker.ts
// Deploy with: wrangler deploy

// ── ESP32 usage notes ────────────────────────────────────────────────────────
/**
 * On ESP32 (Arduino / ESP-IDF):
 *
 * 1. Build the auth URL via HTTP GET to this Worker's /qr endpoint,
 *    OR construct it manually (see embedded-esp32.h for a C helper).
 *
 * 2. Display QR code using QRCode library (qrcode.h or TJpgDec + lvgl).
 *
 * 3. Poll GET https://wyltek-joyid-auth.workers.dev/session/<id>
 *    - 404 → keep polling (every 2s)
 *    - 200 → parse JSON, extract pubkey + signature
 *
 * 4. Verify P-256 signature using mbedTLS:
 *    mbedtls_ecdsa_verify(&ctx, hash, 32, &Q, &r, &s)
 *    (see embedded-esp32.h for full example)
 *
 * 5. Store verified pubkey in NVS — this becomes the device's "owner key".
 *    Future unlock: device signs a challenge → phone signs → compare pubkeys.
 */
