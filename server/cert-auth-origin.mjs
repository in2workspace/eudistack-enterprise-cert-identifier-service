/**
 * Política de orígenes de cert-auth: a qué origen se publican los datos del
 * certificado (targetOrigin de postMessage) y quién puede embeber la página en
 * un iframe (frame-ancestors).
 *
 * El `?origin=` que llega en la URL solo se acepta si es un origen estático
 * conocido o un subdominio de tenant hermano de `frontendOrigin` (mismo
 * esquema, dominio padre y puerto). Sin esta validación, una web ajena podría
 * embeber cert-auth con `?origin=<atacante>` y recibir el certificado del usuario.
 *
 * La cabecera frame-ancestors se construye solo a partir de la configuración,
 * nunca del parámetro recibido.
 */
export function createCertAuthOriginPolicy({ frontendOrigin, landingOrigin = frontendOrigin, staticOrigins = [] }) {
  const frontendUrl = new URL(frontendOrigin);
  // cgcom.stg.eudistack.net → stg.eudistack.net
  const tenantParentDomain = frontendUrl.hostname.split('.').slice(1).join('.');
  // Sin dominio padre con punto (p. ej. localhost) no se admiten subdominios.
  const allowsTenantSubdomains = tenantParentDomain.includes('.');
  const knownOrigins = new Set([frontendOrigin, landingOrigin, ...staticOrigins]);

  const portSuffix = frontendUrl.port ? `:${frontendUrl.port}` : '';
  const tenantWildcard = `${frontendUrl.protocol}//*.${tenantParentDomain}${portSuffix}`;
  const frameAncestors = [...knownOrigins, ...(allowsTenantSubdomains ? [tenantWildcard] : [])];

  function isTenantSibling(candidate) {
    let url;
    try {
      url = new URL(candidate);
    } catch {
      return false;
    }
    const [label, ...parent] = url.hostname.split('.');
    return (
      allowsTenantSubdomains &&
      url.origin === candidate &&
      url.protocol === frontendUrl.protocol &&
      url.port === frontendUrl.port &&
      parent.join('.') === tenantParentDomain &&
      /^[a-z0-9-]+$/.test(label)
    );
  }

  /** Origen de confianza para `candidate`, o `fallback` si no está permitido. */
  function resolveTrustedOrigin(candidate, fallback = frontendOrigin) {
    if (!candidate) return fallback;
    if (knownOrigins.has(candidate) || isTenantSibling(candidate)) return candidate;
    return fallback;
  }

  /**
   * Fija las cabeceras de seguridad de cert-auth en `res` (frame-ancestors; sin
   * caché ni MIME sniffing, porque la respuesta lleva datos personales del
   * certificado) y devuelve el origen de confianza para el `?origin=` recibido.
   */
  function guard(res, candidate, fallback = frontendOrigin) {
    res.setHeader('Content-Security-Policy', `frame-ancestors ${frameAncestors.join(' ')}`);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return resolveTrustedOrigin(candidate, fallback);
  }

  return { resolveTrustedOrigin, guard };
}

/** `url` es exactamente `path` o `path` con querystring. */
export function isPath(url, path) {
  return url === path || (url ?? '').startsWith(`${path}?`);
}

/**
 * Expresión JS segura para incrustar `value` en un <script> inline:
 * encodeURIComponent elimina los caracteres con significado en HTML/JS
 * (<, >, ", \, espacios, saltos de línea) y el navegador lo decodifica al ejecutar.
 */
export function scriptStringLiteral(value) {
  return `decodeURIComponent("${encodeURIComponent(value)}")`;
}

/** Página que publica `CERT_AUTH_ERROR` al portal (popup u iframe) y se cierra. */
export function certAuthErrorPage(error, targetOrigin) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
<script>
  if (window.opener || window.parent !== window) {
    (window.opener || window.parent).postMessage(
      { type: 'CERT_AUTH_ERROR', error: ${scriptStringLiteral(error)} },
      ${scriptStringLiteral(targetOrigin)}
    );
  }
  window.close();
</script>
</body></html>`;
}

/**
 * Desarrollo local: landing de cert-auth que lanza el handshake mTLS en un iframe
 * oculto hacia `mtlsOrigin` y reenvía el resultado al portal (popup o iframe).
 */
export function localDevLandingPage({ openerOrigin, mtlsOrigin, mtlsPort, styles }) {
  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Certificado Digital - CGCOM</title>
  <style>
    ${styles}
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

  <!-- Hidden iframe that triggers the mTLS handshake on port ${mtlsPort}.
       Propaga el origin real del tenant (R-5): el server mTLS no tiene forma
       de resolverlo por sí mismo (puerto directo, sin Host de tenant). -->
  <iframe id="mtls-frame" src="${mtlsOrigin}/cert-auth?origin=${encodeURIComponent(openerOrigin)}"></iframe>

  <script>
    const FRONTEND = ${scriptStringLiteral(openerOrigin)};
    const MTLS = '${mtlsOrigin}';
    let resolved = false;

    // Embedded mode (hidden iframe in the portal, no popup): tell the portal the
    // landing loaded and the mTLS handshake is in progress, so it keeps waiting
    // for the user's certificate selection instead of treating the load as a failure.
    if (!window.opener && window.parent !== window) {
      window.parent.postMessage({ type: 'CERT_AUTH_PENDING' }, FRONTEND);
    }

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

        if (window.opener || window.parent !== window) {
          (window.opener || window.parent).postMessage(
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

        if (window.opener || window.parent !== window) {
          (window.opener || window.parent).postMessage(
            { type: 'CERT_AUTH_ERROR', error: 'No se ha proporcionado certificado' },
            FRONTEND
          );
        }
      } else if (event.data?.type === 'CERT_IFRAME_ERROR') {
        card.innerHTML =
          '<h2>Error</h2>' +
          '<p class="error">' + (event.data.error || 'Error al procesar el certificado') + '</p>' +
          '<button class="retry-btn" onclick="retry()">Reintentar</button>';

        if (window.opener || window.parent !== window) {
          (window.opener || window.parent).postMessage(
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

      if (window.opener || window.parent !== window) {
        (window.opener || window.parent).postMessage(
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
        '${mtlsOrigin}/cert-auth?origin=' + encodeURIComponent(FRONTEND) + '&t=' + Date.now();
    }
  </script>
</body>
</html>`;
}

/** Lista de orígenes separada por comas (variable de entorno) → array sin vacíos. */
export function parseOriginList(value) {
  return (value ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}
