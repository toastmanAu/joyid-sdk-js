/**
 * embedded-esp32.h — JoyID embedded auth for ESP32 (Arduino / ESP-IDF)
 *
 * Implements the polling-based JoyID auth flow for headless/display devices.
 * Uses mbedTLS (bundled with ESP-IDF) for P-256/secp256r1 signature verification.
 *
 * Usage:
 *   #include "embedded-esp32.h"
 *
 *   JoyIDEmbedded joyid("https://wyltek-joyid-auth.workers.dev");
 *   String qrURL = joyid.beginAuth("WyVault", "https://wyltek.io");
 *   displayQR(qrURL);                          // show on screen
 *
 *   JoyIDCredential cred;
 *   if (joyid.poll(cred, 300000)) {            // wait up to 5 min
 *     if (joyid.verify(cred)) {
 *       Serial.println("Owner: " + cred.address);
 *       saveOwnerKey(cred.pubkeyHex);          // store in NVS
 *     }
 *   }
 *
 * Dependencies:
 *   - WiFiClientSecure (ESP Arduino core)
 *   - HTTPClient
 *   - ArduinoJson
 *   - mbedtls (bundled with ESP-IDF — no install needed)
 *   - QRCode library (for display — optional, you can use any QR renderer)
 */

#pragma once
#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

// ── Credential ────────────────────────────────────────────────────────────────

struct JoyIDCredential {
  String address;     // CKB address (ckb1q...)
  String pubkeyHex;   // Uncompressed P-256 pubkey (04 + 64 bytes = 130 hex chars)
  String keyType;     // "main" or "sub"
  String signature;   // Hex-encoded DER signature over the challenge
  String challenge;   // Original challenge that was signed
  bool   valid;
};

// ── JoyIDEmbedded ─────────────────────────────────────────────────────────────

class JoyIDEmbedded {
public:
  explicit JoyIDEmbedded(const char* workerURL,
                          const char* joyidAppURL = "https://app.joyid.dev")
    : _workerURL(workerURL), _joyidAppURL(joyidAppURL) {}

  /**
   * Generate a session ID and build the JoyID auth URL.
   * Display this as a QR code.
   *
   * @param title      App name shown in JoyID UI
   * @param logo       Logo URL shown in JoyID UI (optional)
   * @returns          Full JoyID auth URL to encode as QR
   */
  String beginAuth(const char* title, const char* logo = "") {
    _sessionId = _generateSessionId();
    String callback = String(_workerURL) + "/callback?session=" + _sessionId;

    // Build JoyID URL manually (mirrors buildJoyIDURL in the TS SDK)
    // _data_ param = base64url(JSON({ redirectURL, title, logo, ... }))
    String payload = "{\"redirectURL\":\"" + callback + "\""
                   + ",\"title\":\"" + String(title) + "\""
                   + (strlen(logo) ? String(",\"logo\":\"") + logo + "\"" : "")
                   + ",\"requestNetwork\":\"nervos\"}";

    String encoded = _base64urlEncode(payload);
    return String(_joyidAppURL) + "/auth?type=redirect&_data_=" + encoded;
  }

  /**
   * Poll the Worker for the credential.
   * Call this in a loop or with a timeout — blocks until credential arrives or times out.
   *
   * @param out        Populated on success
   * @param timeoutMs  Max wait time in ms (default 300s)
   * @param intervalMs Poll interval in ms (default 2s)
   * @returns          true if credential received and parsed
   */
  bool poll(JoyIDCredential& out, uint32_t timeoutMs = 300000, uint32_t intervalMs = 2000) {
    String url = String(_workerURL) + "/session/" + _sessionId;
    uint32_t start = millis();

    while (millis() - start < timeoutMs) {
      HTTPClient http;
      WiFiClientSecure client;
      client.setInsecure(); // TODO: pin Worker cert for production

      http.begin(client, url);
      int code = http.GET();

      if (code == 200) {
        String body = http.getString();
        http.end();
        return _parseCredential(body, out);
      }
      http.end();

      // 404 = pending, anything else = error (keep trying)
      delay(intervalMs);
    }
    return false;  // timed out
  }

  /**
   * Verify the P-256 signature in the credential.
   * Uses mbedTLS — available on all ESP32 variants via ESP-IDF.
   *
   * The challenge signed by JoyID is SHA-256(clientDataJSON).
   * We verify: ECDSA_P256_verify(pubkey, SHA256(challenge), signature)
   *
   * @returns true if signature is valid for the pubkey
   */
  bool verify(const JoyIDCredential& cred) {
    if (cred.pubkeyHex.length() < 130) return false;  // need 04+64bytes

    // Decode pubkey (uncompressed: 04 || x || y)
    uint8_t pubkey[65];
    _hexToBytes(cred.pubkeyHex.c_str(), pubkey, 65);

    // Decode signature (DER encoded)
    uint8_t sig[72];
    size_t sigLen = _hexToBytes(cred.signature.c_str(), sig, sizeof(sig));

    // Hash the challenge
    uint8_t hash[32];
    uint8_t challengeBytes[cred.challenge.length()];
    cred.challenge.getBytes(challengeBytes, sizeof(challengeBytes));
    mbedtls_sha256(challengeBytes, cred.challenge.length(), hash, 0);

    // Set up ECDSA context on P-256
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1);

    // Load public key point
    int ret = mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, pubkey, 65);
    if (ret != 0) { mbedtls_ecdsa_free(&ctx); return false; }

    // Parse DER signature into (r, s)
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    // DER: 30 len 02 rlen r 02 slen s
    size_t offset = 4;  // skip 30 len 02 rlen
    uint8_t rlen = sig[3];
    mbedtls_mpi_read_binary(&r, sig + offset, rlen);
    offset += rlen + 2;  // skip r, 02, slen
    uint8_t slen = sig[offset - 1];
    mbedtls_mpi_read_binary(&s, sig + offset, slen);

    ret = mbedtls_ecdsa_verify(&ctx.grp, hash, 32, &ctx.Q, &r, &s);

    mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ctx);
    return ret == 0;
  }

  String sessionId() { return _sessionId; }

private:
  const char* _workerURL;
  const char* _joyidAppURL;
  String _sessionId;

  String _generateSessionId() {
    String id = "";
    for (int i = 0; i < 16; i++) {
      id += String(esp_random() & 0xFF, HEX);
    }
    return id;
  }

  // Minimal base64url encoder (no padding)
  String _base64urlEncode(const String& input) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    String out;
    const uint8_t* src = (const uint8_t*)input.c_str();
    size_t len = input.length();
    for (size_t i = 0; i < len; i += 3) {
      uint32_t b = src[i] << 16;
      if (i+1 < len) b |= src[i+1] << 8;
      if (i+2 < len) b |= src[i+2];
      out += b64[(b >> 18) & 63];
      out += b64[(b >> 12) & 63];
      if (i+1 < len) out += b64[(b >>  6) & 63];
      if (i+2 < len) out += b64[(b      ) & 63];
    }
    return out;
  }

  size_t _hexToBytes(const char* hex, uint8_t* out, size_t maxLen) {
    size_t len = strlen(hex) / 2;
    if (len > maxLen) len = maxLen;
    for (size_t i = 0; i < len; i++) {
      char hi = hex[i*2], lo = hex[i*2+1];
      out[i] = ((hi >= 'a' ? hi-'a'+10 : hi >= 'A' ? hi-'A'+10 : hi-'0') << 4)
             |  (lo >= 'a' ? lo-'a'+10 : lo >= 'A' ? lo-'A'+10 : lo-'0');
    }
    return len;
  }

  bool _parseCredential(const String& json, JoyIDCredential& out) {
    JsonDocument doc;
    if (deserializeJson(doc, json) != DeserializationError::Ok) return false;
    out.address   = doc["address"]   | "";
    out.pubkeyHex = doc["pubkey"]    | "";
    out.keyType   = doc["keyType"]   | "";
    out.signature = doc["signature"] | "";
    out.challenge = doc["challenge"] | "";
    out.valid     = out.address.length() > 0 && out.pubkeyHex.length() > 0;
    return out.valid;
  }
};
