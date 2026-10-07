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

/** Lista de orígenes separada por comas (variable de entorno) → array sin vacíos. */
export function parseOriginList(value) {
  return (value ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}
