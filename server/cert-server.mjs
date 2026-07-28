/**
 * CGCOM Certificate Authentication Server
 *
 * Two-server architecture to handle Chrome/Windows TLS behaviour:
 *
 *   1. Regular HTTPS server (port 3443) — no client-cert request.
 *      Serves the popup landing page that always loads reliably.
 *
 *   2. mTLS HTTPS server (port 3444) — requests a client certificate.
 *      The landing page embeds an iframe pointing here; the iframe
 *      extracts X.509 attributes and posts them back via postMessage.
 *
 * This avoids the problem where Chrome cancels the entire TLS connection
 * when the user dismisses the certificate-selection dialog, which prevented
 * the popup page from loading and sending postMessage back to the portal.
 *
 * Usage:
 *   node server/cert-server.mjs
 */

// Permite conexiones HTTPS a localhost con certificados mkcert (solo dev).
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

import http from 'node:http';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';
import forge from 'node-forge';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CERTS_DIR = path.join(__dirname, 'certs');
const PORT = parseInt(process.env.CERT_PORT || '8080');
const MTLS_PORT = parseInt(process.env.MTLS_PORT || '3444');
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';
// Origin of the popup page as seen by the browser (nginx URL in production, localhost in standalone mode)
const LANDING_ORIGIN = process.env.LANDING_ORIGIN || FRONTEND_ORIGIN;
// Direct URL to the mTLS server — must be reachable by the browser (Docker port mapping or NLB)
const MTLS_ORIGIN = process.env.MTLS_ORIGIN || `https://localhost:${MTLS_PORT}`;
const BOOTSTRAP_TOKEN = process.env.BOOTSTRAP_TOKEN || '';
// Explicit override for non-standard topologies; unset by default — the issuer
// URL and tenant are resolved per-request from the caller's own Host (below),
// so one running instance serves every tenant subdomain correctly (R-5).
const ISSUER_URL_OVERRIDE = process.env.ISSUER_URL || '';
const ISSUER_TENANT_OVERRIDE = process.env.ISSUER_TENANT || '';
const ALLOWED_ORIGINS = new Set([
  FRONTEND_ORIGIN,
  'http://localhost:3001',
]);

/**
 * Host público real (con puerto) de la petición entrante. nginx setea `Host`
 * con `$host` (SIN puerto) pero `X-Forwarded-Host` con `$http_host` (CON
 * puerto) — hay que preferir este último o cualquier URL construida a partir
 * de él (X-Forwarded-Host hacia el issuer, credential-offer, wallet callback)
 * pierde el puerto en cualquier setup que no use el 443/80 por defecto (dev
 * local en :4443), rompiendo la wallet aunque el tenant se resuelva bien.
 */
function requestHost(req) {
  return req.headers['x-forwarded-host'] || req.headers.host;
}

/** Primer segmento del hostname (sin puerto), en minúsculas — mismo algoritmo que resolveTenantIdentity() del frontend (AD-3). */
function resolveTenantFromHost(host) {
  if (!host) return null;
  const hostname = host.split(':')[0].toLowerCase();
  const segments = hostname.split('.');
  return segments.length >= 2 && segments[0].length > 0 ? segments[0] : null;
}

/** Organización "mandataria" (empleador) por tenant — mismos valores que EMPLOYEE_DEMO_PROFILE en eudistack-cgcom-mfe-cert-identifier, para que la credencial emitida coincida con lo que vio el titular en pantalla. */
const EMPLOYEE_MANDATOR_BY_TENANT = {
  calidalia: {
    commonName: 'Gallo',
    organization: 'Gallo',
    organizationIdentifier: 'VATES-Q2802224G',
    serialNumber: 'Q2802224G',
    email: 'info@gallo.es',
  },
};

const DEFAULT_EMPLOYEE_MANDATOR = {
  commonName: 'Altia Consultoría y Tecnología',
  organization: 'Altia Consultoría y Tecnología',
  organizationIdentifier: 'VATES-A15726083',
  serialNumber: 'A15726083',
  email: 'info@altia.es',
};

/**
 * Payload `learcredential.employee.sd.1` (mandate.mandator/mandatee/power) —
 * todo tenant que no sea CGCOM emite esta credencial LEARCredentialEmployee
 * en vez de doctorid.sd.1 (que solo CGCOM tiene registrado en su
 * tenant_credential_profile, postgres/seed-tenants.sql). El backend del
 * Issuer envuelve el payload completo bajo "mandate" cuando
 * credentialSubjectStrategy no es "direct" (GenericCredentialBuilder), así
 * que aquí NO se anida bajo "mandate" — mandator/mandatee/power van al
 * nivel superior del payload.
 */
function buildEmployeeBootstrapPayload({ firstName, lastName, email, userData, tenant }) {
  const mandator = EMPLOYEE_MANDATOR_BY_TENANT[tenant] || DEFAULT_EMPLOYEE_MANDATOR;

  return {
    credential_configuration_id: 'learcredential.employee.sd.1',
    payload: {
      mandator: {
        commonName: mandator.commonName,
        country: 'ES',
        email: mandator.email,
        organization: mandator.organization,
        organizationIdentifier: mandator.organizationIdentifier,
        serialNumber: mandator.serialNumber,
      },
      mandatee: {
        employeeId: userData.collegiateNumber || '20240001',
        email,
        firstName,
        lastName,
        // additionalProperty (schema allows additionalProperties: true) — the
        // Verifier embeds the whole mandatee object in the id_token
        // (id_token_embed: "mandate.mandatee"), so it travels through to
        // "Datos del Empleado" after a later OIDC login with this credential.
        // jobTitle/Puesto is intentionally NOT sourced from here — it's a
        // per-tenant hardcoded display value in oidc.service.ts, not part of
        // the credential (demo data, not a real HR system).
        nationalId: userData.dni || '12345678A',
      },
      // domain must equal the tenant (mfe-credential-manager's AuthService.hasPower()
      // requires power.domain === the tenant resolved from the hostname to grant
      // access — a fixed 'DOME' domain here rejected every non-DOME tenant's login
      // to the Issuer with "session scoped to a different tenant").
      power: [
        { domain: tenant, function: 'Onboarding', action: 'Execute', type: 'Domain' },
      ],
    },
    delivery: 'ui',
    email,
    grant_type: 'authorization_code',
  };
}

/** Origin same-origin de la petición entrante (protocolo real vía X-Forwarded-Proto detrás de nginx). */
function resolveRequestOrigin(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  return `${proto}://${requestHost(req)}`;
}

// ─── Certificate management ─────────────────────────────────────────────────

function ensureCerts() {
  const keyPath = path.join(CERTS_DIR, 'server.key');
  const certPath = path.join(CERTS_DIR, 'server.crt');

  if (existsSync(keyPath) && existsSync(certPath)) {
    console.log('Usando certificados de servidor existentes en', CERTS_DIR);
    return;
  }

  console.log('No se encontraron certificados. Generando con node-forge (autofirmados)...');
  console.log('Para certificados de confianza local usa: mkcert -install && mkcert -key-file server/certs/server.key -cert-file server/certs/server.crt localhost 127.0.0.1');
  mkdirSync(CERTS_DIR, { recursive: true });

  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const caCert = forge.pki.createCertificate();
  caCert.publicKey = caKeys.publicKey;
  caCert.serialNumber = '01';
  caCert.validity.notBefore = new Date();
  caCert.validity.notAfter = new Date();
  caCert.validity.notAfter.setFullYear(caCert.validity.notBefore.getFullYear() + 10);

  const caAttrs = [
    { name: 'commonName', value: 'CGCOM Demo CA' },
    { name: 'organizationName', value: 'CGCOM Demo' },
    { name: 'countryName', value: 'ES' },
  ];
  caCert.setSubject(caAttrs);
  caCert.setIssuer(caAttrs);
  caCert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true },
  ]);
  caCert.sign(caKeys.privateKey, forge.md.sha256.create());

  const serverKeys = forge.pki.rsa.generateKeyPair(2048);
  const serverCert = forge.pki.createCertificate();
  serverCert.publicKey = serverKeys.publicKey;
  serverCert.serialNumber = '02';
  serverCert.validity.notBefore = new Date();
  serverCert.validity.notAfter = new Date();
  serverCert.validity.notAfter.setFullYear(serverCert.validity.notBefore.getFullYear() + 5);

  serverCert.setSubject([
    { name: 'commonName', value: 'localhost' },
    { name: 'organizationName', value: 'CGCOM Demo' },
    { name: 'countryName', value: 'ES' },
  ]);
  serverCert.setIssuer(caAttrs);
  serverCert.setExtensions([
    { name: 'subjectAltName', altNames: [
      { type: 2, value: 'localhost' },
      { type: 7, ip: '127.0.0.1' },
    ]},
  ]);
  serverCert.sign(caKeys.privateKey, forge.md.sha256.create());

  writeFileSync(path.join(CERTS_DIR, 'ca.crt'), forge.pki.certificateToPem(caCert));
  writeFileSync(path.join(CERTS_DIR, 'server.key'), forge.pki.privateKeyToPem(serverKeys.privateKey));
  writeFileSync(path.join(CERTS_DIR, 'server.crt'), forge.pki.certificateToPem(serverCert));

  console.log('Certificados autofirmados generados en', CERTS_DIR);
}

// ─── X.509 attribute extraction (mirrors onboarding x509util.go) ────────────

const OID_MAP = {
  '2.5.4.3': 'commonName',
  '2.5.4.4': 'surname',
  '2.5.4.5': 'serialNumber', // DNI in Spanish certificates
  '2.5.4.6': 'country',
  '2.5.4.7': 'locality',
  '2.5.4.8': 'province',
  '2.5.4.9': 'streetAddress',
  '2.5.4.10': 'organization',
  '2.5.4.11': 'organizationalUnit',
  '2.5.4.17': 'postalCode',
  '2.5.4.42': 'givenName',
  '2.5.4.97': 'organizationIdentifier',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

// Maps Node.js TLS short-names / OIDs to our field names (used for non-RSA fallback)
const TLS_ATTR_MAP = {
  CN: 'commonName',
  SN: 'surname',
  serialNumber: 'serialNumber',
  C: 'country',
  L: 'locality',
  ST: 'province',
  O: 'organization',
  OU: 'organizationalUnit',
  GN: 'givenName',
  givenName: 'givenName',
  emailAddress: 'emailAddress',
  organizationIdentifier: 'organizationIdentifier',
  '2.5.4.97': 'organizationIdentifier',
};

/**
 * Re-interpret a string whose code-points are actually UTF-8 bytes
 * (forge decodes ASN.1 UTF8String / BMPString as Latin-1 code-points).
 */
function fixEncoding(str) {
  if (typeof str !== 'string') return str;
  try {
    const bytes = new Uint8Array([...str].map(c => c.charCodeAt(0)));
    const decoded = new TextDecoder('utf-8').decode(bytes);
    if (!decoded.includes('\uFFFD')) return decoded;
  } catch { /* fall through */ }
  return str;
}

function mapAttributes(attrs) {
  const result = {};
  for (const attr of attrs) {
    const oid = attr.type;
    const fieldName = OID_MAP[oid] || attr.shortName || oid;
    result[fieldName] = fixEncoding(attr.value);
  }
  return result;
}

// Parses Node.js X509Certificate subject/issuer multiline format ("CN=Foo\nO=Bar\n...")
function parseX509Name(name) {
  const result = {};
  for (const line of name.split('\n')) {
    const eqIdx = line.indexOf('=');
    if (eqIdx < 0) continue;
    const key = line.slice(0, eqIdx).trim();
    const value = line.slice(eqIdx + 1).trim();
    result[TLS_ATTR_MAP[key] || key] = value;
  }
  return result;
}

function extractCertificateAttributes(rawDerBuffer, peerCert) {
  // Primary path: node-forge (RSA certificates, full encoding correction)
  try {
    const derHex = rawDerBuffer.toString('binary');
    const asn1 = forge.asn1.fromDer(derHex);
    const cert = forge.pki.certificateFromAsn1(asn1);

    const subject = mapAttributes(cert.subject.attributes);
    const issuer = mapAttributes(cert.issuer.attributes);

    const certType = subject.organizationIdentifier
      ? 'organizational'
      : 'personal';

    return {
      subject,
      issuer,
      validFrom: cert.validity.notBefore.toISOString(),
      validTo: cert.validity.notAfter.toISOString(),
      certificateType: certType,
    };
  } catch (forgeErr) {
    // Fallback 1: crypto.X509Certificate — built-in Node.js, supports all key types
    // (ECDSA, Ed25519, RSA-PSS…). Works for both ALB path (DER from header) and
    // direct mTLS path. forge only fails on the public-key algorithm, not on the
    // subject/issuer/validity fields we actually need.
    console.warn(`forge parse failed (${forgeErr.message}), falling back to crypto.X509Certificate`);
    try {
      const x509 = new X509Certificate(rawDerBuffer);
      const subject = parseX509Name(x509.subject);
      const issuer  = parseX509Name(x509.issuer);
      const certType = subject.organizationIdentifier ? 'organizational' : 'personal';
      return {
        subject,
        issuer,
        validFrom: new Date(x509.validFrom).toISOString(),
        validTo:   new Date(x509.validTo).toISOString(),
        certificateType: certType,
      };
    } catch (x509Err) {
      // Fallback 2: peerCert TLS attributes (direct mTLS path only — no DER in ALB path)
      console.warn(`X509Certificate fallback failed (${x509Err.message}), trying peerCert`);
      if (!peerCert) {
        console.error('No peerCert available; cannot parse non-RSA certificate');
        return null;
      }
      try {
        const mapTls = (nodeAttrs) => {
          const result = {};
          for (const [k, v] of Object.entries(nodeAttrs)) {
            result[TLS_ATTR_MAP[k] || k] = v;
          }
          return result;
        };
        const subject = mapTls(peerCert.subject);
        const issuer  = mapTls(peerCert.issuer);
        const certType = subject.organizationIdentifier ? 'organizational' : 'personal';
        return {
          subject,
          issuer,
          validFrom: new Date(peerCert.valid_from).toISOString(),
          validTo:   new Date(peerCert.valid_to).toISOString(),
          certificateType: certType,
        };
      } catch (nativeErr) {
        console.error('Error parseando certificado (nativo):', nativeErr.message);
        return null;
      }
    }
  }
}

// ─── HTML helpers ───────────────────────────────────────────────────────────

const COMMON_STYLES = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; display: flex;
         justify-content: center; align-items: center; min-height: 100vh;
         background: #f3f4f6; color: #1f2937; }
  .card { background: white; border-radius: 12px; padding: 2rem;
          max-width: 520px; width: 90%;
          box-shadow: 0 4px 6px rgba(0,0,0,.1); text-align: center; }
  h2 { color: #1A5276; margin-bottom: .75rem; }
  .success { color: #16a34a; }
  .error   { color: #dc2626; }
  .spinner { display: inline-block; width: 24px; height: 24px;
             border: 3px solid #e5e7eb; border-top: 3px solid #1A5276;
             border-radius: 50%; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  p { margin: .5rem 0; line-height: 1.5; }
`;

function htmlPage(title, body) {
  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>${COMMON_STYLES}</style>
</head>
<body>
  <div class="card">${body}</div>
</body>
</html>`;
}

// ─── Shared TLS options ─────────────────────────────────────────────────────

ensureCerts();

const tlsKey = readFileSync(path.join(CERTS_DIR, 'server.key'));
const tlsCert = readFileSync(path.join(CERTS_DIR, 'server.crt'));

// ─── Server 1: HTTP (behind ALB/nginx) — port 8080 ─────────────────────────
// Serves the popup landing page and API endpoints under /identify/*.
// TLS is terminated by the ALB/nginx; this server speaks plain HTTP.

function corsHeaders(res, req) {
  const origin = req?.headers?.origin || '';
  // Same-origin call through nginx (any tenant subdomain) or a known static dev origin.
  const isSameOrigin = origin === resolveRequestOrigin(req);
  const allowed = isSameOrigin || ALLOWED_ORIGINS.has(origin) ? origin : FRONTEND_ORIGIN;
  res.setHeader('Access-Control-Allow-Origin', allowed);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

const regularServer = http.createServer((req, res) => {
  corsHeaders(res, req);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ── Popup landing page with iframe to mTLS server ───────────────────────
  if (req.url === '/identify/api/cert-auth' || req.url?.startsWith('/identify/api/cert-auth?')) {
    const reqUrl = new URL(req.url, 'http://localhost');
    const openerOrigin = reqUrl.searchParams.get('origin') || FRONTEND_ORIGIN;

    // ── ALB mTLS mode (STG): cert delivered via header ────────────────────
    const albCertPem = req.headers['x-amzn-mtls-clientcert'];
    if (albCertPem) {
      try {
        const pem = decodeURIComponent(albCertPem);
        const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
        const derBuffer = Buffer.from(b64, 'base64');
        const certData = extractCertificateAttributes(derBuffer);

        if (!certData) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
<script>
  if (window.opener) {
    window.opener.postMessage(
      { type: 'CERT_AUTH_ERROR', error: 'Error al procesar el certificado digital' },
      ${JSON.stringify(openerOrigin)}
    );
  }
  window.close();
</script>
</body></html>`);
          return;
        }

        const certDataJSON = JSON.stringify(certData);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <title>Certificado leído — CGCOM</title>
  <style>${COMMON_STYLES}</style>
</head>
<body>
  <div class="card">
    <h2 class="success">Certificado leído correctamente</h2>
    <p>Enviando datos al portal...</p>
    <p><span class="spinner"></span></p>
  </div>
  <script>
    if (window.opener) {
      window.opener.postMessage(
        { type: 'CERT_AUTH_SUCCESS', data: ${certDataJSON} },
        ${JSON.stringify(openerOrigin)}
      );
      setTimeout(() => window.close(), 1200);
    }
  </script>
</body>
</html>`);
        return;
      } catch (err) {
        console.error('Error procesando cert ALB mTLS:', err.message);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
<script>
  if (window.opener) {
    window.opener.postMessage(
      { type: 'CERT_AUTH_ERROR', error: 'Error interno al leer el certificado' },
      ${JSON.stringify(openerOrigin)}
    );
  }
  window.close();
</script>
</body></html>`);
        return;
      }
    }

    // ── Local dev mode: serve iframe page (mTLS on MTLS_ORIGIN) ──────────

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Certificado Digital - CGCOM</title>
  <style>
    ${COMMON_STYLES}
    iframe { display: none; }
    .retry-btn {
      display: inline-block; margin-top: 1rem; padding: .5rem 1.5rem;
      background: #E67E22; color: white; border: none; border-radius: 8px;
      font-weight: 600; cursor: pointer; font-size: .95rem;
    }
    .retry-btn:hover { background: #D35400; }
  </style>
</head>
<body>
  <div class="card" id="content">
    <h2>Certificado Digital</h2>
    <p><span class="spinner"></span></p>
    <p>Selecciona tu certificado en el diálogo del navegador...</p>
    <p style="font-size:.85rem;color:#6b7280;margin-top:.5rem;">
      Si no aparece el diálogo, asegúrate de tener un certificado digital instalado.
    </p>
  </div>

  <!-- Hidden iframe that triggers the mTLS handshake on port ${MTLS_PORT}.
       Propaga el origin real del tenant (R-5): el server mTLS no tiene forma
       de resolverlo por sí mismo (puerto directo, sin Host de tenant). -->
  <iframe id="mtls-frame" src="${MTLS_ORIGIN}/cert-auth?origin=${encodeURIComponent(openerOrigin)}"></iframe>

  <script>
    const FRONTEND = '${openerOrigin}';
    const MTLS = '${MTLS_ORIGIN}';
    let resolved = false;

    // Listen for postMessage from the mTLS iframe
    window.addEventListener('message', (event) => {
      if (event.origin !== MTLS) return;
      resolved = true;

      const card = document.getElementById('content');

      if (event.data?.type === 'CERT_IFRAME_SUCCESS') {
        card.innerHTML =
          '<h2 class="success">Certificado leído correctamente</h2>' +
          '<p>Enviando datos al portal...</p>' +
          '<p><span class="spinner"></span></p>';

        if (window.opener) {
          window.opener.postMessage(
            { type: 'CERT_AUTH_SUCCESS', data: event.data.data },
            FRONTEND
          );
          setTimeout(() => window.close(), 1200);
        }
      } else if (event.data?.type === 'CERT_IFRAME_NO_CERT') {
        card.innerHTML =
          '<h2>Certificado Digital</h2>' +
          '<p class="error">No se ha proporcionado ningún certificado digital.</p>' +
          '<p>Asegúrate de tener un certificado digital instalado ' +
          '(ej: FNMT) y de seleccionarlo cuando el navegador lo solicite.</p>' +
          '<button class="retry-btn" onclick="retry()">Reintentar</button>';

        if (window.opener) {
          window.opener.postMessage(
            { type: 'CERT_AUTH_ERROR', error: 'No se ha proporcionado certificado' },
            FRONTEND
          );
        }
      } else if (event.data?.type === 'CERT_IFRAME_ERROR') {
        card.innerHTML =
          '<h2>Error</h2>' +
          '<p class="error">' + (event.data.error || 'Error al procesar el certificado') + '</p>' +
          '<button class="retry-btn" onclick="retry()">Reintentar</button>';

        if (window.opener) {
          window.opener.postMessage(
            { type: 'CERT_AUTH_ERROR', error: event.data.error || 'Error al procesar el certificado' },
            FRONTEND
          );
        }
      }
    });

    // Timeout: if the iframe doesn't respond within 15s, the mTLS
    // handshake probably failed (user canceled, no certs, etc.)
    setTimeout(() => {
      if (resolved) return;
      resolved = true;
      const card = document.getElementById('content');
      card.innerHTML =
        '<h2>Certificado Digital</h2>' +
        '<p class="error">No se pudo conectar con el servidor de certificados.</p>' +
        '<p>Es posible que no tengas un certificado digital instalado, ' +
        'o que hayas cancelado la selección.</p>' +
        '<button class="retry-btn" onclick="retry()">Reintentar</button>';

      if (window.opener) {
        window.opener.postMessage(
          { type: 'CERT_AUTH_ERROR', error: 'No se pudo completar la lectura del certificado. Verifica que tienes un certificado digital instalado.' },
          FRONTEND
        );
      }
    }, 15000);

    function retry() {
      resolved = false;
      document.getElementById('content').innerHTML =
        '<h2>Certificado Digital</h2>' +
        '<p><span class="spinner"></span></p>' +
        '<p>Selecciona tu certificado en el diálogo del navegador...</p>';
      document.getElementById('mtls-frame').src =
        '${MTLS_ORIGIN}/cert-auth?origin=' + encodeURIComponent(FRONTEND) + '&t=' + Date.now();
    }
  </script>
</body>
</html>`);
    return;
  }

  // ── Bootstrap endpoint (proxy al issuer CGCOM) ─────────────────────────
  if (req.url === '/identify/api/bootstrap' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', async () => {
      try {
        const userData = JSON.parse(body);
        const nameParts = (userData.name || '').trim().split(' ');
        const firstName = nameParts[0] || 'María';
        const lastName = nameParts.slice(1).join(' ') || 'García López';
        const email = userData.email || 'maria.garcia@cgcom.es';

        // credential_configuration_id por tenant (R-6): solo CGCOM tiene
        // 'doctorid.sd.1' registrado en su tenant_credential_profile
        // (postgres/seed-tenants.sql) — el resto de tenants (calidalia,
        // dome, kpmg, sandbox...) solo tienen 'learcredential.employee.sd.1'.
        // Enviar doctorid.sd.1 a un tenant sin ese perfil hace que el Issuer
        // rechace el bootstrap, rompiendo "añadir credencial" para cualquier
        // tenant que no sea CGCOM.
        const tenantForPayload = resolveTenantFromHost(requestHost(req)) || ISSUER_TENANT_OVERRIDE;
        const bootstrapPayload =
          tenantForPayload === 'cgcom'
            ? {
                credential_configuration_id: 'doctorid.sd.1',
                payload: {
                  firstName,
                  lastName,
                  registrationNumber: userData.collegiateNumber || '282801234',
                  nationalId: userData.dni || '12345678A',
                  provincialBoard: 'COM Barcelona',
                  specialty: 'Medicina Interna',
                  email,
                  country: 'ES',
                },
                delivery: 'ui',
                email,
                grant_type: 'authorization_code',
              }
            : buildEmployeeBootstrapPayload({ firstName, lastName, email, userData, tenant: tenantForPayload });

        // Tenant, issuer y X-Forwarded-* se resuelven por petición desde el Host
        // con el que el navegador llamó a este servicio — mismo tenant que la
        // pantalla que disparó el bootstrap, nunca un valor fijo (R-5, bug con
        // tenant "dome"/"calidalia"). ISSUER_URL apunta al servicio interno de
        // Docker (bypassa nginx), así que el Issuer solo puede saber el host
        // público real (para las URLs que embebe en la credential offer: token
        // endpoint, credential endpoint, wallet callback) a través de estos
        // X-Forwarded-* — usar el FRONTEND_ORIGIN estático aquí generaba una
        // credential offer con URLs de cgcom aunque el tenant bootstrapeado
        // (X-Tenant) fuera el correcto, rompiendo la wallet en cualquier otro
        // tenant.
        const tenant = tenantForPayload;
        const issuerUrl = ISSUER_URL_OVERRIDE || `${resolveRequestOrigin(req)}/issuer/api/v1/bootstrap`;
        const forwardedProto = req.headers['x-forwarded-proto'] || 'https';
        const forwardedHost = requestHost(req) || new URL(FRONTEND_ORIGIN).host;
        const issuerRes = await fetch(issuerUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Bootstrap-Token': BOOTSTRAP_TOKEN,
            ...(tenant ? { 'X-Tenant': tenant } : {}),
            'X-Forwarded-Proto': forwardedProto,
            'X-Forwarded-Host': forwardedHost,
          },
          body: JSON.stringify(bootstrapPayload),
          signal: AbortSignal.timeout(10_000),
        });

        if (!issuerRes.ok) {
          res.writeHead(issuerRes.status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Issuer respondió con ${issuerRes.status}` }));
          return;
        }

        const location = issuerRes.headers.get('location');
        if (!location) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'El issuer no devolvió header Location' }));
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ credentialOfferUrl: location }));
      } catch (err) {
        console.error('Error en /api/bootstrap:', err.message);
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // ── Health check ───────────────────────────────────────────────────────
  if (req.url === '/identify/health' || req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'UP' }));
    return;
  }

  // ── Landing page ───────────────────────────────────────────────────────
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(
      htmlPage(
        'CGCOM Certificate Server',
        `
      <h2>Servidor de Certificados CGCOM</h2>
      <p>Este servidor solicita certificados digitales del navegador
         y extrae los atributos X.509 para el portal de emisión.</p>
      <p style="margin-top:1rem;">
        <a href="/cert-auth"
           style="color:#E67E22;font-weight:600;">
          Probar autenticación con certificado
        </a>
      </p>
      <p style="margin-top:.5rem;font-size:.85rem;color:#6b7280;">
        Puerto: ${PORT} (landing) / ${MTLS_PORT} (mTLS) &middot; Frontend: ${FRONTEND_ORIGIN}
      </p>`,
      ),
    );
    return;
  }

  res.writeHead(404);
  res.end('Not Found');
});

// ─── Server 2: mTLS HTTPS (requests client cert) — port 3444 ───────────────
// Only serves the /cert-auth endpoint. Responses are sent via postMessage
// to the parent frame (the landing page on port 3443).

const mtlsServer = https.createServer(
  { key: tlsKey, cert: tlsCert, requestCert: true, rejectUnauthorized: false },
  (req, res) => {
    // Origin real del tenant, propagado por query param desde la landing page
    // (R-5): este server no tiene Host de tenant propio (puerto directo 3444),
    // así que LANDING_ORIGIN solo es fallback para llamadas sin el param.
    const reqUrl = new URL(req.url, `https://localhost:${MTLS_PORT}`);
    const targetOrigin = reqUrl.searchParams.get('origin') || LANDING_ORIGIN;

    // Allow the landing page to embed this in an iframe
    res.setHeader('Access-Control-Allow-Origin', targetOrigin);

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.url === '/cert-auth' || req.url?.startsWith('/cert-auth?')) {
      const peerCert = req.socket.getPeerCertificate(true);

      if (!peerCert || !peerCert.raw) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
<script>
  window.parent.postMessage(
    { type: 'CERT_IFRAME_NO_CERT' },
    ${JSON.stringify(targetOrigin)}
  );
</script>
</body></html>`);
        return;
      }

      const certData = extractCertificateAttributes(peerCert.raw, peerCert);

      if (!certData) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
<script>
  window.parent.postMessage(
    { type: 'CERT_IFRAME_ERROR', error: 'Error al procesar el certificado digital' },
    ${JSON.stringify(targetOrigin)}
  );
</script>
</body></html>`);
        return;
      }

      const certDataJSON = JSON.stringify(certData);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
<script>
  window.parent.postMessage(
    { type: 'CERT_IFRAME_SUCCESS', data: ${certDataJSON} },
    ${JSON.stringify(targetOrigin)}
  );
</script>
</body></html>`);
      return;
    }

    res.writeHead(404);
    res.end('Not Found');
  },
);

// ─── Start both servers ─────────────────────────────────────────────────────

regularServer.listen(PORT, () => {
  console.log(`\n  Servidor de Certificados CGCOM`);
  console.log(`  HTTP:     http://localhost:${PORT}  (behind nginx/ALB)`);
  console.log(`  mTLS:     https://localhost:${MTLS_PORT}  (direct, browser port mapping)`);
  console.log(`  Popup:    ${LANDING_ORIGIN}/identify/api/cert-auth`);
  console.log(`  Frontend: ${FRONTEND_ORIGIN}`);
});

mtlsServer.listen(MTLS_PORT, () => {
  console.log(`\n  Servidor mTLS escuchando en puerto ${MTLS_PORT}`);
  console.log(`  Si usas certificados mkcert, el navegador confiará automáticamente.`);
  console.log(`  Si usas autofirmados, abre https://localhost:${PORT} y acepta el aviso.\n`);
});
