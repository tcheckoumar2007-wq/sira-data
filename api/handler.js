const cloudinary = require('cloudinary').v2;
const crypto = require('crypto');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const FIREBASE_API_KEY    = process.env.FIREBASE_API_KEY;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;

// Photos acceptées : JPEG, PNG, WebP, HEIC, 3 Mo maximum (Vercel refuse
// les requêtes de plus de 4,5 Mo, et le base64 grossit l'image d'un tiers).
const MAX_IMAGE_BYTES = 3 * 1024 * 1024;
const DATA_URL = /^data:image\/(jpeg|jpg|png|webp|heic|heif);base64,([A-Za-z0-9+/=\s]+)$/;
// Identifiant de lieu : chiffres, lettres, tirets et soulignés seulement.
const PLACE_ID = /^[A-Za-z0-9_-]{1,80}$/;

// ── Vérifie un ID token Firebase et renvoie l'uid (ou null) ───────────
async function verifyFirebaseToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const idToken = authHeader.substring(7).trim();
  if (!idToken) return null;

  try {
    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );

    if (!response.ok) return null;

    const data = await response.json();
    const user = data.users && data.users[0];
    return user && user.localId ? user.localId : null;
  } catch (err) {
    console.error('[verifyFirebaseToken]', err);
    return null;
  }
}

// ── Handler principal ─────────────────────────────────
module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const path = (req.url || '').split('?')[0].replace('/api', '') || '/';

  // ── GET /health ─────────────────────────────────────
  if (req.method === 'GET' && path === '/health') {
    return res.json({
      status:  'ok',
      app:     'Sira API',
      version: '2.1.0',
    });
  }

  // ── GET /config ─────────────────────────────────────
  // Public : renvoie uniquement les clés Firebase publiques (la clé API
  // Firebase n'est pas un secret : la sécurité vient des règles Firestore).
  if (req.method === 'GET' && path === '/config') {
    return res.json({
      success:   true,
      apiKey:    FIREBASE_API_KEY,
      projectId: FIREBASE_PROJECT_ID,
    });
  }

  // ── À partir d'ici : auth Firebase obligatoire ──────
  const authHeader = req.headers.authorization || req.headers.Authorization;
  const uid = await verifyFirebaseToken(authHeader);

  if (!uid) {
    return res.status(401).json({
      success: false,
      error:   'Authentification requise',
    });
  }

  // ── POST /upload ────────────────────────────────────
  if (req.method === 'POST' && path === '/upload') {
    try {
      const { imageBase64, placeId } = req.body || {};

      // Seule une image envoyée en base64 est acceptée : jamais une URL
      // (Cloudinary irait sinon télécharger n'importe quelle adresse).
      const match = typeof imageBase64 === 'string' ? DATA_URL.exec(imageBase64) : null;
      if (!match) {
        return res.status(400).json({
          success: false,
          error:   'Image manquante ou format non accepté (JPEG, PNG, WebP, HEIC).',
        });
      }
      const sizeBytes = Math.floor((match[2].replace(/\s/g, '').length * 3) / 4);
      if (sizeBytes > MAX_IMAGE_BYTES) {
        return res.status(413).json({
          success: false,
          error:   'Image trop lourde (3 Mo maximum).',
        });
      }
      if (typeof placeId !== 'string' || !PLACE_ID.test(placeId)) {
        return res.status(400).json({
          success: false,
          error:   'Identifiant de lieu invalide.',
        });
      }

      // Dossier et nom choisis par le serveur : un utilisateur ne peut ni
      // écrire ailleurs ni remplacer la photo de quelqu'un d'autre.
      const result = await cloudinary.uploader.upload(imageBase64, {
        folder:         `sira/places/${placeId}`,
        public_id:      `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`,
        overwrite:      false,
        resource_type:  'image',
        context:        { uploader: uid },
        transformation: [
          { width: 1024, height: 1024, crop: 'limit' },
          { quality: 'auto:good' },
          { fetch_format: 'auto' },
        ],
      });

      return res.json({
        success:  true,
        url:      result.secure_url,
        publicId: result.public_id,
      });
    } catch (error) {
      console.error('[upload]', error);
      // Pas de détail technique renvoyé au téléphone.
      return res.status(500).json({
        success: false,
        error:   "L'envoi de la photo a échoué.",
      });
    }
  }

  // ── Route non trouvée ───────────────────────────────
  return res.status(404).json({
    success: false,
    error:   'Route non trouvée',
  });
};
