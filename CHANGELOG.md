# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **EUD-38 — allowlist de licencias unificada**: `.github/license-policy.json` es ahora la transcripción íntegra de `conv-quality-security-gates.md` §16.1, idéntica en los trece repositorios con gate. Añade `LGPL-2.1-only`, la grafía SPDX vigente del mismo permiso que `LGPL-2.1`, que ya estaba admitido: `logback` 1.5.34 la declara así y el gate la bloqueaba por la grafía, no por la licencia. Incorpora también las cuatro entradas que faltaban en este repositorio respecto de la convención (`EPL-1.0`, `LGPL-2.1`, `GPL-2.0-with-classpath-exception`, `Python-2.0`): una divergencia local de la política no es una decisión del repositorio, es un defecto.

### Added

- **EUD-220 — SBOM CycloneDX and License Gate**: Added CycloneDX 1.6 SBOM generation (`npm run sbom`), CI license compliance gate (`license-gate.yml`), and automated SBOM asset attachment to GitHub Releases. The evaluator is vendored at `.github/scripts/license-gate.mjs` with its own `node --test` suite, which the gate workflow runs before evaluating anything: this repository verifies itself without depending on any other one. Free-text upstream license names resolve through a reviewed SPDX equivalence table instead of piling up as expiring exceptions, and the `CODEOWNERS` rules that protect the policy, the exception register and the evaluator sit at the END of the file, because GitHub applies the last matching pattern.
