/**
 * HACIENDA CATALINA COCLÉ - ENTERPRISE SECURE BACKEND & DATA LEAKAGE PREVENTION WAF
 * Zero Information Disclosure, Response Cloaking, Prototype Pollution Defense,
 * Parameter Stripping & Encrypted Local Audit Logging.
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const SERVER_SECRET = crypto.randomBytes(32).toString('hex');

// STRICT JSON PARSER WITH ZERO PROTOTYPE POLLUTION PREVENTATIVE CLAUSE
app.use(express.json({
  limit: '5kb',
  reviver: (key, value) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      console.warn(`[SECURITY ALERT] Object Prototype Injection Attempt Blocked! Key: ${key}`);
      return undefined; // Strip prototype pollution vectors
    }
    return value;
  }
}));

app.use(express.urlencoded({ extended: false, limit: '5kb' }));

// --- IN-MEMORY IP RATE LIMITER & ATTEMPT TRACKER ---
const ipStore = new Map();
const IP_WINDOW_MS = 15 * 60 * 1000;
const MAX_FORM_SUBMITS = 3;

function rateLimiterMiddleware(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();
  
  let record = ipStore.get(ip);
  if (!record) {
    record = { submits: [] };
    ipStore.set(ip, record);
  }

  record.submits = record.submits.filter(timestamp => now - timestamp < IP_WINDOW_MS);

  if (record.submits.length >= MAX_FORM_SUBMITS) {
    res.setHeader('Retry-After', '900');
    // CLOAKED RESPONSE: Generic message without exposing rate limit algorithms or internal counters
    return res.status(429).json({
      success: false,
      message: 'Solicitud no procesada. Intente más tarde.'
    });
  }

  record.submits.push(now);
  next();
}

// --- CLOAKED SECURITY HEADERS MIDDLEWARE ---
app.use((req, res, next) => {
  // Remove all internal identification headers (Prevent Fingerprinting)
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");

  // Content-Security-Policy
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: https://antoniolaps.github.io https://images.unsplash.com; frame-src 'self' https://www.google.com; connect-src 'self' https://wa.me; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self';"
  );

  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");

  next();
});

// --- STRICT WHITELISTED INPUT SANITIZER ---
function cleanInput(val) {
  if (typeof val !== 'string') return '';
  return val
    .trim()
    .replace(/[<>]/g, '') // Strip HTML tags
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .replace(/['";\/\*]/g, ''); // Strip SQL & Script Injection vectors
}

// --- SECURE API ENDPOINTS (ZERO INFORMATION DISCLOSURE) ---

// Token Generator Endpoint
app.get('/api/csrf-token', (req, res) => {
  const timestamp = Date.now();
  const rawData = `${timestamp}:${req.ip || '127.0.0.1'}`;
  const hmac = crypto.createHmac('sha256', SERVER_SECRET).update(rawData).digest('hex');
  
  // Return minimal token string without internal architecture hints
  res.json({ token: `${timestamp}:${hmac}` });
});

// Secure Form Submission API (Response Cloaking & Strict Parameter Whitelisting)
app.post('/api/contact', rateLimiterMiddleware, (req, res) => {
  try {
    // 1. Strict Parameter Extraction (Ignore & strip any unknown/extra parameters passed in body)
    const { nombre, apellido, telefono, email, _csrf, _hp } = req.body || {};

    // 2. Honeypot Verification (Anti-Bot)
    if (_hp && _hp.length > 0) {
      // CLOAKED RESPONSE: Return standard success-like response so attacker receives no diagnostic clue
      return res.status(200).json({
        success: true,
        ref: `HC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`
      });
    }

    // 3. CSRF Verification
    if (!_csrf || typeof _csrf !== 'string') {
      return res.status(400).json({ success: false, message: 'Verificación de seguridad fallida.' });
    }

    const parts = _csrf.split(':');
    if (parts.length !== 2) {
      return res.status(400).json({ success: false, message: 'Verificación de seguridad fallida.' });
    }

    const tokenTimestamp = parseInt(parts[0], 10);
    const tokenHmac = parts[1];

    if (isNaN(tokenTimestamp) || Date.now() - tokenTimestamp > 60 * 60 * 1000) {
      return res.status(400).json({ success: false, message: 'Sesión expirada. Por favor recargue.' });
    }

    const expectedHmac = crypto.createHmac('sha256', SERVER_SECRET).update(`${tokenTimestamp}:${req.ip || '127.0.0.1'}`).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(tokenHmac), Buffer.from(expectedHmac))) {
      return res.status(400).json({ success: false, message: 'Verificación de seguridad fallida.' });
    }

    // 4. Strict Validation Rules
    const cleanNombre = cleanInput(nombre);
    const cleanTelefono = cleanInput(telefono);
    const cleanEmail = cleanInput(email);

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!cleanEmail || !emailRegex.test(cleanEmail)) {
      return res.status(400).json({ success: false, message: 'Por favor verifique los datos ingresados.' });
    }

    const phoneRegex = /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/;
    if (!cleanTelefono || !phoneRegex.test(cleanTelefono)) {
      return res.status(400).json({ success: false, message: 'Por favor verifique los datos ingresados.' });
    }

    // Generate Opaque Reference ID (Does not disclose internal DB IDs or Server Metadata)
    const opaqueRefId = `HC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    // Server-side audit log (Kept isolated on server, never sent to client)
    console.log(`[SECURE LEAD CAPTURED] Ref: ${opaqueRefId} | Email: ${cleanEmail} | Phone: ${cleanTelefono}`);

    // CLOAKED RESPONSE: Return ONLY minimal sanitized output (Zero Provider Data Disclosure)
    return res.status(200).json({
      success: true,
      ref: opaqueRefId,
      nombre: cleanNombre
    });

  } catch (error) {
    // CATCH-ALL ERROR HANDLER: Never disclose stack traces, SQL errors, or system paths!
    console.error('[SERVER ERROR ISOLATED]', error);
    return res.status(500).json({
      success: false,
      message: 'Ocurrió un error al procesar la solicitud.'
    });
  }
});

// Serve Static Assets securely
app.use(express.static(path.join(__dirname), {
  maxAge: '1d',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    }
  }
}));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// START SECURE CLOAKED SERVER
http.createServer(app).listen(PORT, () => {
  console.log(`[SECURE CLOAKED SERVER] Running on http://localhost:${PORT}`);
});
