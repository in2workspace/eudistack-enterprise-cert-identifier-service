# eudistack-cgcom-cert-identifier-service

Backend del **Portal de Identificación con certificado FNMT** de CGCOM.

> ⚠️ **Material de demo.** Extraído tal cual de `eudistack-platform-dev/dev-tools/demo-cgcom`
> (vibecoding para demos, no producto). No sigue todavía el stack ni el SDD de EUDIStack.
> Relacionado con las Épicas [EUDISTACK-622](https://eudistack.atlassian.net/browse/EUDISTACK-622)
> (Identificación con certificado FNMT) y [EUDISTACK-621](https://eudistack.atlassian.net/browse/EUDISTACK-621).

## Qué hace

Dos piezas:

1. **`server/cert-server.mjs`** — servidor mTLS de doble puerto (Node + `node-forge`):
   - HTTPS normal (`3443`) — sirve la landing del popup y expone `/api/bootstrap`.
   - mTLS (`3444`) — solicita el certificado de cliente X.509, extrae sus atributos
     y los devuelve al frontal vía `postMessage`. Workaround del comportamiento TLS
     de Chrome/Windows cuando el usuario cancela el diálogo de selección de certificado.

2. **`api/bootstrap.js`** — variante *serverless* (Vercel) del endpoint `/api/bootstrap`:
   construye el payload `doctorid.sd.1` y llama al issuer CGCOM con `X-Bootstrap-Token`
   (evita CORS y no expone el token en el cliente).

## Ejecución local

```bash
npm install
npm run cert-server     # arranca 3443 (HTTPS) + 3444 (mTLS)
```

Variables de entorno:

| Var | Default | Uso |
|-----|---------|-----|
| `CERT_PORT` | `3443` | Puerto HTTPS normal |
| `MTLS_PORT` | `3444` | Puerto mTLS |
| `FRONTEND_ORIGIN` | `http://localhost:3000` | Origen permitido para `postMessage` |
| `BOOTSTRAP_TOKEN` | *(hardcoded en `api/bootstrap.js`)* | Token de bootstrap del issuer |

## ⚠️ Deuda conocida (heredada de la demo)

- **`api/bootstrap.js` lleva un `BOOTSTRAP_TOKEN` hardcodeado** como fallback. Debe moverse
  a variable de entorno / secreto antes de cualquier uso no-demo.
- `server/certs/*.key` está en `.gitignore`. El `.crt`/`.ca` se versionan por comodidad de demo;
  regenéralos para cualquier entorno real (`cert-server.mjs` los crea si no existen).
- Sin tests, sin CI, sin observabilidad. Fuera de `repository-map.md` y del SDD.

## Origen

Repo creado por separación de `demo-cgcom` (3 repos: este backend + frontal de identificación
`eudistack-cgcom-mfe-cert-identifier` + portal de emisión `eudistack-cgcom-mfe-issuance-portal`).
