const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const SIRA_TOKEN          = process.env.SIRA_SECRET_TOKEN;
const FIREBASE_API_KEY    = process.env.FIREBASE_API_KEY;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;

// ── Format serverless Vercel ──────────────────────────
module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, x-sira-token');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const path  = req.url.replace('/api', '') || '/';
  const token = req.headers['x-sira-token'];

  // ── GET /health ─────────────────────────────────────
  if (req.method === 'GET' && path === '/health') {
    return res.json({
      status:  'ok',
      app:     'Sira API',
      version: '1.0.0'
    });
  }

  // ── Vérifie le token pour les autres routes ──────────
  if (token !== SIRA_TOKEN) {
    return res.status(401).json({
      success: false,
      error:   'Non autorisé'
    });
  }

  // ── GET /config ──────────────────────────────────────
  if (req.method === 'GET' && path === '/config') {
    return res.json({
      success:   true,
      apiKey:    FIREBASE_API_KEY,
      projectId: FIREBASE_PROJECT_ID
    });
  }

  // ── POST /upload ─────────────────────────────────────
  if (req.method === 'POST' && path === '/upload') {
    try {
      const { imageBase64, folder, placeId } = req.body;

      if (!imageBase64) {
        return res.status(400).json({
          success: false,
          error:   'Image manquante'
        });
      }

      const result = await cloudinary.uploader.upload(imageBase64, {
        folder:         folder || 'sira/places',
        public_id:      placeId || undefined,
        transformation: [
          { width: 1024, height: 1024, crop: 'limit' },
          { quality: 'auto:good' },
          { fetch_format: 'auto' }
        ]
      });

      return res.json({
        success:  true,
        url:      result.secure_url,
        publicId: result.public_id
      });

    } catch (error) {
      return res.status(500).json({
        success: false,
        error:   error.message
      });
    }
  }

  // ── Route non trouvée ────────────────────────────────
  return res.status(404).json({
    success: false,
    error:   'Route non trouvée'
  });
};
