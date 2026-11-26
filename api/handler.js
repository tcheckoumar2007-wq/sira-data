// Sira API — version 3 (sécurité renforcée)
//
// Routes :
//   GET  /api/health  : état du service (public)
//   GET  /api/config  : clé Firebase publique + projet (public, limité en débit)
//   POST /api/upload  : envoi d'une photo de lieu (compte Sira obligatoire)
//
// Variables d'environnement (Vercel > Settings > Environment Variables) :
//   obligatoires : FIREBASE_API_KEY, FIREBASE_PROJECT_ID,
//                  CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
//   facultatives : ALLOWED_ORIGINS        (sites autorisés à appeler l'API depuis
//                                          un navigateur, séparés par des virgules)
//                  UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN
//                                         (limite de requêtes partagée entre
//                                          toutes les instances, gratuit)

const cloudinary = require('cloudinary').v2;
const crypto = require('crypto');

// ── Configuration ─────────────────────────────────────────────────────
const REQUIRED_ENV = [
  'FIREBASE_API_KEY',
  'FIREBASE_PROJECT_ID',
  'CLOUDINARY_CLOUD_NAME',
  'CLOUDINARY_API_KEY',
  'CLOUDINARY_API_SECRET',
];
const missingEnv = REQUIRED_ENV.filter((name) => !process.env[name]);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

// Photos : JPEG, PNG, WebP, HEIC, 3 Mo maximum (Vercel refuse les requêtes
// de plus de 4,5 Mo, et le base64 grossit l'image d'un tiers).
const MAX_IMAGE_BYTES = 3 * 1024 * 1024;
const DATA_URL = /^data:image\/(jpeg|jpg|png|webp|heic|heif);base64,([A-Za-z0-9+/=]+)$/;
const PLACE_ID = /^[A-Za-z0-9_-]{1,80}$/;
const ID_TOKEN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

// Limites de requêtes (par fenêtre de temps).
const LIMITS = {
  // Large, car en Afrique beaucoup d'abonnés mobiles partagent la même IP.
  config: { max: 300, windowSec: 60 },     // par adresse IP
  authFail: { max: 50, windowSec: 600 },   // échecs d'authentification par IP
  upload: { max: 20, windowSec: 3600 },    // photos par compte et par heure
};

// ── Journal de sécurité (visible dans Vercel > Logs) ─────────────────
function securityLog(event, details) {
  console.warn(JSON.stringify({ type: 'security', event, at: new Date().toISOString(), ...details }));
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'inconnue';
}

// Empreinte courte : on ne garde jamais l'adresse IP en clair dans les logs.
function hashId(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
}

// ── Limite de requêtes ───────────────────────────────────────────────
// Avec Upstash (si configuré) : compteur partagé entre toutes les instances.
// Sinon : compteur en mémoire, par instance (protection partielle).
const memoryBuckets = new Map();

async function hitLimit(bucket, key, { max, windowSec }) {
  const id = `sira:${bucket}:${key}`;
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (url && token) {
    try {
      const response = await fetch(`${url}/pipeline`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify([
          ['INCR', id],
          ['EXPIRE', id, String(windowSec), 'NX'],
        ]),
      });
      if (response.ok) {
        const [incr] = await response.json();
        return Number(incr && incr.result) > max;
      }
    } catch (err) {
      console.error('[rate-limit] Upstash indisponible, compteur local utilisé');
    }
  }
  const now = Date.now();
  const entry = memoryBuckets.get(id);
  if (!entry || entry.resetAt <= now) {
    memoryBuckets.set(id, { count: 1, resetAt: now + windowSec * 1000 });
    if (memoryBuckets.size > 5000) {
      for (const [k, v] of memoryBuckets) if (v.resetAt <= now) memoryBuckets.delete(k);
    }
    return false;
  }
  entry.count += 1;
  return entry.count > max;
}

// ── Réponses ─────────────────────────────────────────────────────────
function setSecurityHeaders(res) {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control', 'no-store');
}

// CORS : l'application mobile n'envoie pas d'en-tête Origin et n'est pas
// concernée. Un navigateur n'est accepté que depuis un site de la liste.
function applyCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const sameHost = req.headers.host && origin === `https://${req.headers.host}`;
  if (sameHost || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '600');
    return true;
  }
  return false;
}

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

const fail = (res, status, error) => send(res, status, { success: false, error });

// ── Authentification : vérifie le jeton Firebase ─────────────────────
// Renvoie l'uid, ou null si le jeton est absent, invalide, expiré, ou si le
// compte est désactivé.
async function verifyFirebaseToken(authHeader) {
  if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) return null;
  const idToken = authHeader.slice(7).trim();
  if (!idToken || idToken.length > 4096 || !ID_TOKEN.test(idToken)) return null;
  try {
    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(FIREBASE_API_KEY)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );
    if (!response.ok) return null;
    const data = await response.json();
    const user = data.users && data.users[0];
    if (!user || !user.localId || user.disabled) return null;
    return user.localId;
  } catch (err) {
    console.error('[auth] vérification impossible');
    return null;
  }
}

// Le lieu existe-t-il, et l'utilisateur a-t-il le droit de le lire ?
// (les règles Firestore décident : un domicile n'est lisible que par son
// créateur). On utilise le jeton de l'utilisateur lui-même.
async function canSeePlace(placeId, authHeader) {
  try {
    const url =
      `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(FIREBASE_PROJECT_ID)}` +
      `/databases/(default)/documents/places/${encodeURIComponent(placeId)}` +
      `?key=${encodeURIComponent(FIREBASE_API_KEY)}&mask.fieldPaths=deleted`;
    const response = await fetch(url, { headers: { Authorization: authHeader } });
    if (!response.ok) return false;
    const doc = await response.json();
    const deleted = doc.fields && doc.fields.deleted && doc.fields.deleted.booleanValue === true;
    return !deleted;
  } catch (err) {
    console.error('[upload] lecture du lieu impossible');
    return false;
  }
}

// Le contenu est-il vraiment une image du type annoncé ? (on lit les
// premiers octets, on ne fait pas confiance au type déclaré).
function looksLikeImage(buffer) {
  if (buffer.length < 12) return false;
  const hex = buffer.subarray(0, 12).toString('hex');
  if (hex.startsWith('ffd8ff')) return true;                       // JPEG
  if (hex.startsWith('89504e470d0a1a0a')) return true;             // PNG
  if (hex.startsWith('52494646') && buffer.subarray(8, 12).toString('ascii') === 'WEBP') return true;
  const box = buffer.subarray(4, 12).toString('ascii');            // HEIC / HEIF
  return /^ftyp(heic|heix|hevc|hevx|mif1|msf1)$/.test(box);
}

// ── Routes ───────────────────────────────────────────────────────────
async function handleUpload(req, res, uid, authHeader) {
  if (await hitLimit('upload', uid, LIMITS.upload)) {
    securityLog('upload_rate_limited', { user: hashId(uid) });
    return fail(res, 429, 'Trop de photos envoyées. Réessayez plus tard.');
  }

  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const { imageBase64, placeId } = body;

  if (typeof placeId !== 'string' || !PLACE_ID.test(placeId)) {
    return fail(res, 400, 'Identifiant de lieu invalide.');
  }
  // Seule une image en base64 est acceptée, jamais une URL (Cloudinary
  // irait sinon télécharger n'importe quelle adresse).
  const match = typeof imageBase64 === 'string' ? DATA_URL.exec(imageBase64) : null;
  if (!match) {
    return fail(res, 400, 'Image manquante ou format non accepté (JPEG, PNG, WebP, HEIC).');
  }
  const bytes = Buffer.from(match[2], 'base64');
  if (bytes.length === 0) return fail(res, 400, 'Image vide.');
  if (bytes.length > MAX_IMAGE_BYTES) return fail(res, 413, 'Image trop lourde (3 Mo maximum).');
  if (!looksLikeImage(bytes)) {
    securityLog('upload_not_an_image', { user: hashId(uid) });
    return fail(res, 400, "Le fichier envoyé n'est pas une image valide.");
  }
  if (!(await canSeePlace(placeId, authHeader))) {
    securityLog('upload_unknown_place', { user: hashId(uid) });
    return fail(res, 404, 'Lieu introuvable.');
  }

  try {
    // Dossier et nom choisis par le serveur : impossible d'écrire ailleurs
    // ou de remplacer la photo de quelqu'un d'autre.
    const result = await cloudinary.uploader.upload(`data:image/${match[1]};base64,${match[2]}`, {
      folder: `sira/places/${placeId}`,
      public_id: `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`,
      overwrite: false,
      resource_type: 'image',
      context: { uploader: uid },
      transformation: [
        { width: 1024, height: 1024, crop: 'limit' },
        { quality: 'auto:good' },
        { fetch_format: 'auto' },
      ],
    });
    return send(res, 200, { success: true, url: result.secure_url, publicId: result.public_id });
  } catch (err) {
    console.error('[upload] échec Cloudinary');
    return fail(res, 500, "L'envoi de la photo a échoué.");
  }
}

module.exports = async (req, res) => {
  setSecurityHeaders(res);
  const ip = clientIp(req);

  // HTTPS obligatoire (Vercel redirige déjà, ceci est une sécurité de plus).
  const proto = req.headers['x-forwarded-proto'];
  if (proto && proto !== 'https') return fail(res, 400, 'HTTPS obligatoire.');

  if (!applyCors(req, res)) {
    securityLog('cors_refused', { ip: hashId(ip), origin: String(req.headers.origin).slice(0, 100) });
    return fail(res, 403, 'Origine non autorisée.');
  }
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  if (missingEnv.length) {
    console.error('[config] variables manquantes :', missingEnv.join(', '));
    return fail(res, 503, 'Service temporairement indisponible.');
  }

  const path = (req.url || '').split('?')[0].replace(/^\/api/, '') || '/';

  if (path === '/health') {
    if (req.method !== 'GET') return fail(res, 405, 'Méthode non autorisée.');
    return send(res, 200, { status: 'ok' });
  }

  // La clé Firebase n'est pas un secret (la sécurité vient des règles
  // Firestore et des restrictions de la clé dans Google Cloud).
  if (path === '/config') {
    if (req.method !== 'GET') return fail(res, 405, 'Méthode non autorisée.');
    if (await hitLimit('config', hashId(ip), LIMITS.config)) {
      return fail(res, 429, 'Trop de requêtes. Réessayez dans une minute.');
    }
    return send(res, 200, { success: true, apiKey: FIREBASE_API_KEY, projectId: FIREBASE_PROJECT_ID });
  }

  if (path !== '/upload') return fail(res, 404, 'Route non trouvée.');
  if (req.method !== 'POST') return fail(res, 405, 'Méthode non autorisée.');

  // ── À partir d'ici : compte Sira obligatoire ──────────────────────
  const authHeader = req.headers.authorization;
  const uid = await verifyFirebaseToken(authHeader);
  if (!uid) {
    const blocked = await hitLimit('authfail', hashId(ip), LIMITS.authFail);
    securityLog(blocked ? 'auth_fail_blocked' : 'auth_fail', { ip: hashId(ip), path });
    return fail(res, blocked ? 429 : 401, blocked ? 'Trop de tentatives. Réessayez plus tard.' : 'Authentification requise.');
  }

  return handleUpload(req, res, uid, authHeader);
};

// Exporté pour les tests.
module.exports._internals = { looksLikeImage, hitLimit, memoryBuckets };
