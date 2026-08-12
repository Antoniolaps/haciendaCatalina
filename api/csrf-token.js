const crypto = require('crypto');

const SERVER_SECRET = process.env.SERVER_SECRET || 'hacienda_catalina_secure_secret_key_2026';

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  const timestamp = Date.now();
  const rawData = `${timestamp}:${req.headers['x-forwarded-for'] || '127.0.0.1'}`;
  const hmac = crypto.createHmac('sha256', SERVER_SECRET).update(rawData).digest('hex');

  res.status(200).json({ token: `${timestamp}:${hmac}` });
};
