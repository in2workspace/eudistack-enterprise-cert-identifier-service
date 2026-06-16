/**
 * Vercel Serverless Function — /api/bootstrap
 *
 * Proxy al issuer CGCOM. Construye el payload doctorid.sd.1 a partir de los
 * datos del médico y llama al issuer con el X-Bootstrap-Token.
 * Así se evita CORS y no se expone el token en el cliente.
 */

const ISSUER_URL = 'https://issuer.cgcom.demo.fikua.com/api/v1/bootstrap';
const BOOTSTRAP_TOKEN = process.env.BOOTSTRAP_TOKEN || 'd8511b7c-3617-4509-8cf0-283477841ddc';

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const userData = req.body || {};
    const nameParts = (userData.name || '').trim().split(' ');
    const firstName = nameParts[0] || 'María';
    const lastName = nameParts.slice(1).join(' ') || 'García López';

    const bootstrapPayload = {
      credential_configuration_id: 'doctorid.sd.1',
      payload: {
        firstName,
        lastName,
        registrationNumber: userData.collegiateNumber || '282801234',
        nationalId: userData.dni || '12345678A',
        provincialBoard: 'COM Barcelona',
        specialty: 'Medicina Interna',
        email: userData.email || 'maria.garcia@cgcom.es',
        country: 'ES',
      },
      delivery: 'ui',
      email: userData.email || 'maria.garcia@cgcom.es',
      grant_type: 'authorization_code',
    };

    const issuerRes = await fetch(ISSUER_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Bootstrap-Token': BOOTSTRAP_TOKEN,
      },
      body: JSON.stringify(bootstrapPayload),
      signal: AbortSignal.timeout(10_000),
    });

    if (!issuerRes.ok) {
      const data = await issuerRes.json().catch(() => null);
      return res.status(issuerRes.status).json({
        error: `Issuer respondió con ${issuerRes.status}`,
        detail: data,
      });
    }

    const location = issuerRes.headers.get('location');
    if (!location) {
      return res.status(502).json({ error: 'El issuer no devolvió header Location' });
    }

    return res.status(200).json({ credentialOfferUrl: location });
  } catch (err) {
    console.error('Error en /api/bootstrap:', err.message);
    return res.status(502).json({ error: err.message });
  }
}
