const crypto = require('crypto');

const SERVER_SECRET = process.env.SERVER_SECRET || 'hacienda_catalina_secure_secret_key_2026';

function cleanInput(val) {
  if (typeof val !== 'string') return '';
  return val
    .trim()
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .replace(/['";\/\*]/g, '');
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Método no permitido.' });
  }

  try {
    const { nombre, apellido, telefono, email, _csrf, _hp } = req.body || {};

    // 1. Honeypot Anti-Bot Filter
    if (_hp && _hp.length > 0) {
      return res.status(200).json({
        success: true,
        ref: `HC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`
      });
    }

    // 2. Anti-CSRF Token Validation
    if (!_csrf || typeof _csrf !== 'string') {
      return res.status(400).json({ success: false, message: 'Verificación de seguridad no superada.' });
    }

    const parts = _csrf.split(':');
    if (parts.length !== 2) {
      return res.status(400).json({ success: false, message: 'Verificación de seguridad no superada.' });
    }

    const tokenTimestamp = parseInt(parts[0], 10);
    const tokenHmac = parts[1];

    if (isNaN(tokenTimestamp) || Date.now() - tokenTimestamp > 60 * 60 * 1000) {
      return res.status(400).json({ success: false, message: 'Sesión expirada. Por favor recargue.' });
    }

    const ip = req.headers['x-forwarded-for'] || '127.0.0.1';
    const expectedHmac = crypto.createHmac('sha256', SERVER_SECRET).update(`${tokenTimestamp}:${ip}`).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(tokenHmac), Buffer.from(expectedHmac))) {
      return res.status(400).json({ success: false, message: 'Verificación de seguridad no superada.' });
    }

    // 3. Strict Input Validation
    const cleanNombre = cleanInput(nombre);
    const cleanTelefono = cleanInput(telefono);
    const cleanEmail = cleanInput(email);

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!cleanEmail || !emailRegex.test(cleanEmail)) {
      return res.status(400).json({ success: false, message: 'Por favor verifique el correo electrónico ingresado.' });
    }

    const phoneRegex = /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/;
    if (!cleanTelefono || !phoneRegex.test(cleanTelefono)) {
      return res.status(400).json({ success: false, message: 'Por favor verifique el número telefónico ingresado.' });
    }

    // Opaque Reference Code Generation
    const opaqueRefId = `HC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    // Log internally on Vercel Function Logs
    console.log(`[VERCEL LEAD LOG] Ref: ${opaqueRefId} | Email: ${cleanEmail} | Phone: ${cleanTelefono}`);

    // Return Cloaked Response
    return res.status(200).json({
      success: true,
      ref: opaqueRefId,
      nombre: cleanNombre
    });

  } catch (err) {
    console.error('[VERCEL ERROR ISOLATED]', err);
    return res.status(500).json({
      success: false,
      message: 'Error al procesar la solicitud.'
    });
  }
};
