const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const FIREBASE_API_KEY    = process.env.FIREBASE_API_KEY;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;

// ── Vérifie un ID token Firebase ──────────────────────
async function verifyFirebaseToken(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return false;
  }

  const idToken = authHeader.substring(7).trim();
  if (!idToken) return false;

  try {
    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken }),
      }
    );

    if (!response.ok) return false;

    const data = await response.json();
    return !!(data.users && data.users.length > 0);
  } catch (err) {
    console.error('[verifyFirebaseToken]', err);
    return false;
  }
}

// ── Handler principal ─────────────────────────────────
module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const path = req.url.replace('/api', '') || '/';

  // ── GET /health ─────────────────────────────────────
  if (req.method === 'GET' && path === '/health') {
    return res.json({
      status:  'ok',
      app:     'Sira API',
      version: '2.0.0',
    });
  }

  // ── GET /config ─────────────────────────────────────
  // Public : renvoie uniquement les clés Firebase publiques
  if (req.method === 'GET' && path === '/config') {
    return res.json({
      success:   true,
      apiKey:    FIREBASE_API_KEY,
      projectId: FIREBASE_PROJECT_ID,
    });
  }

  // ── À partir d'ici : auth Firebase obligatoire ──────
  const authHeader = req.headers.authorization || req.headers.Authorization;
  const isAuthenticated = await verifyFirebaseToken(authHeader);

  if (!isAuthenticated) {
    return res.status(401).json({
      success: false,
      error:   'Authentification requise',
    });
  }

  // ── POST /upload ────────────────────────────────────
  if (req.method === 'POST' && path === '/upload') {
    try {
      const { imageBase64, folder, placeId } = req.body;

      if (!imageBase64) {
        return res.status(400).json({
          success: false,
          error:   'Image manquante',
        });
      }

      const result = await cloudinary.uploader.upload(imageBase64, {
        folder:         folder || 'sira/places',
        public_id:      placeId || undefined,
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
      return res.status(500).json({
        success: false,
        error:   error.message,
      });
    }
  }

  // ── Route non trouvée ───────────────────────────────
  return res.status(404).json({
    success: false,
    error:   'Route non trouvée',
  });
};
