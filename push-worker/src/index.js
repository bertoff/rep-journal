// Rep Journal rest-timer push server.
// The app POSTs /schedule when a rest starts and /cancel when it is skipped.
// One Durable Object per push subscription holds the pending alarm; when the
// alarm fires it sends a Web Push (RFC 8291 aes128gcm + VAPID) to the phone.
import { DurableObject } from 'cloudflare:workers';

const PUSH_HOSTS = ['push.apple.com', 'fcm.googleapis.com', 'push.services.mozilla.com', 'notify.windows.com'];
const MAX_DELAY_SECS = 3600;

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/') return new Response('rep-journal-push ok', { headers: cors });
    if (request.method !== 'POST' || !['/schedule', '/cancel'].includes(url.pathname)) {
      return new Response('not found', { status: 404, headers: cors });
    }

    let body;
    try { body = JSON.parse(await request.text()); } catch { return new Response('bad json', { status: 400, headers: cors }); }

    const endpoint = url.pathname === '/schedule' ? body?.subscription?.endpoint : body?.endpoint;
    if (!isPushEndpoint(endpoint)) return new Response('bad endpoint', { status: 400, headers: cors });

    const stub = env.TIMERS.get(env.TIMERS.idFromName(endpoint));
    if (url.pathname === '/cancel') {
      await stub.cancel();
      return new Response('cancelled', { headers: cors });
    }

    const sub = body.subscription;
    if (!sub?.keys?.p256dh || !sub?.keys?.auth) return new Response('bad keys', { status: 400, headers: cors });
    const delay = Number(body.delay);
    if (!Number.isFinite(delay) || delay < 1 || delay > MAX_DELAY_SECS) return new Response('bad delay', { status: 400, headers: cors });

    await stub.schedule({
      subscription: { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } },
      fireAt: Date.now() + delay * 1000,
      title: String(body.title || 'REST OVER').slice(0, 80),
      body: String(body.body || '').slice(0, 200),
    });
    return new Response('scheduled', { headers: cors });
  },
};

export class RestTimer extends DurableObject {
  async schedule(job) {
    await this.ctx.storage.put('job', job);
    await this.ctx.storage.setAlarm(job.fireAt);
  }

  async cancel() {
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.delete('job');
  }

  async alarm() {
    const job = await this.ctx.storage.get('job');
    await this.ctx.storage.delete('job');
    if (!job) return;
    const payload = JSON.stringify({ title: job.title, body: job.body });
    const res = await sendWebPush(this.env, job.subscription, payload);
    if (!res.ok && res.status !== 404 && res.status !== 410) {
      console.log('push failed', res.status, await res.text());
    }
  }
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());
  return {
    'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : allowed[0] || '',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}

function isPushEndpoint(endpoint) {
  try {
    const u = new URL(endpoint);
    return u.protocol === 'https:' && PUSH_HOSTS.some(h => u.hostname === h || u.hostname.endsWith('.' + h));
  } catch {
    return false;
  }
}

// ── Web Push ────────────────────────────────────────────────────────────────
const enc = new TextEncoder();

function b64urlDecode(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function b64urlEncode(bytes) {
  let bin = '';
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

async function vapidAuthHeader(env, endpoint) {
  const pub = b64urlDecode(env.VAPID_PUBLIC_KEY);
  const key = await crypto.subtle.importKey('jwk', {
    kty: 'EC', crv: 'P-256',
    x: b64urlEncode(pub.slice(1, 33)), y: b64urlEncode(pub.slice(33, 65)),
    d: env.VAPID_PRIVATE_KEY,
  }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const header = b64urlEncode(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64urlEncode(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT,
  })));
  const unsigned = `${header}.${claims}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(unsigned));
  return `vapid t=${unsigned}.${b64urlEncode(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}

// RFC 8291 message encryption, single aes128gcm record.
async function encryptPayload(sub, plaintext) {
  const uaPublic = b64urlDecode(sub.keys.p256dh);
  const authSecret = b64urlDecode(sub.keys.auth);

  const asKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', asKeys.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, asKeys.privateKey, 256));

  const prkKey = await hmac(authSecret, ecdhSecret);
  const keyInfo = concat(enc.encode('WebPush: info\0'), uaPublic, asPublic, new Uint8Array([1]));
  const ikm = await hmac(prkKey, keyInfo);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, concat(enc.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);

  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const record = concat(enc.encode(plaintext), new Uint8Array([2]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, record));

  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096);
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ciphertext);
}

async function sendWebPush(env, sub, payload) {
  const body = await encryptPayload(sub, payload);
  return fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': await vapidAuthHeader(env, sub.endpoint),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '120',
      'Urgency': 'high',
    },
    body,
  });
}
