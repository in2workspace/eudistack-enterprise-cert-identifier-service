# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **cert-auth embebible en iframe**: las páginas de `/issuance-portal/api/cert-auth` publican el resultado a `window.opener` o, si están embebidas, a `window.parent`, para que el portal muestre el selector de certificado sin ventana emergente. En modo local la landing envía `CERT_AUTH_PENDING` al portal al cargar. El modo popup sigue funcionando igual. El parámetro `?origin=` se valida contra los subdominios de tenant de `FRONTEND_ORIGIN` (si no coincide, se usa `FRONTEND_ORIGIN`) y las respuestas llevan `Content-Security-Policy: frame-ancestors` con el origen permitido, para que ninguna web ajena pueda embeber la página y recibir el certificado.
- **EUD-38 — allowlist de licencias unificada**: `.github/license-policy.json` es ahora la transcripción íntegra de `conv-quality-security-gates.md` §16.1, idéntica en los trece repositorios con gate. Añade `LGPL-2.1-only`, la grafía SPDX vigente del mismo permiso que `LGPL-2.1`, que ya estaba admitido: `logback` 1.5.34 la declara así y el gate la bloqueaba por la grafía, no por la licencia. Incorpora también las cuatro entradas que faltaban en este repositorio respecto de la convención (`EPL-1.0`, `LGPL-2.1`, `GPL-2.0-with-classpath-exception`, `Python-2.0`): una divergencia local de la política no es una decisión del repositorio, es un defecto.

### Added

- **EUD-220 — SBOM CycloneDX and License Gate**: Added CycloneDX 1.6 SBOM generation (`npm run sbom`), CI license compliance gate (`license-gate.yml`), and automated SBOM asset attachment to GitHub Releases. The evaluator is vendored at `.github/scripts/license-gate.mjs` with its own `node --test` suite, which the gate workflow runs before evaluating anything: this repository verifies itself without depending on any other one. Free-text upstream license names resolve through a reviewed SPDX equivalence table instead of piling up as expiring exceptions, and the `CODEOWNERS` rules that protect the policy, the exception register and the evaluator sit at the END of the file, because GitHub applies the last matching pattern.
