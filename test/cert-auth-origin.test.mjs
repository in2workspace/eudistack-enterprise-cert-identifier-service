import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCertAuthOriginPolicy, parseOriginList } from '../server/cert-auth-origin.mjs';

const STG = createCertAuthOriginPolicy({
  frontendOrigin: 'https://cgcom.stg.eudistack.net',
});

const LOCAL = createCertAuthOriginPolicy({
  frontendOrigin: 'https://cgcom.127.0.0.1.nip.io:4443',
  staticOrigins: ['http://localhost:3001'],
});

const STANDALONE = createCertAuthOriginPolicy({
  frontendOrigin: 'http://localhost:3000',
  landingOrigin: 'http://localhost:3443',
});

function fakeResponse() {
  const headers = {};
  return { headers, setHeader: (name, value) => { headers[name] = value; } };
}

test('sin origin devuelve el fallback', () => {
  assert.equal(STG.resolveTrustedOrigin(null), 'https://cgcom.stg.eudistack.net');
  assert.equal(STG.resolveTrustedOrigin('', 'https://fallback.example'), 'https://fallback.example');
});

test('acepta FRONTEND_ORIGIN, LANDING_ORIGIN y los orígenes extra configurados', () => {
  assert.equal(STG.resolveTrustedOrigin('https://cgcom.stg.eudistack.net'), 'https://cgcom.stg.eudistack.net');
  assert.equal(STANDALONE.resolveTrustedOrigin('http://localhost:3443'), 'http://localhost:3443');
  assert.equal(LOCAL.resolveTrustedOrigin('http://localhost:3001'), 'http://localhost:3001');
});

test('sin orígenes extra configurados no acepta localhost:3001', () => {
  assert.equal(STG.resolveTrustedOrigin('http://localhost:3001'), 'https://cgcom.stg.eudistack.net');
});

test('acepta subdominios de tenant hermanos de FRONTEND_ORIGIN', () => {
  assert.equal(STG.resolveTrustedOrigin('https://calidalia.stg.eudistack.net'), 'https://calidalia.stg.eudistack.net');
  assert.equal(LOCAL.resolveTrustedOrigin('https://sandbox.127.0.0.1.nip.io:4443'), 'https://sandbox.127.0.0.1.nip.io:4443');
});

test('rechaza orígenes ajenos o malformados y usa el fallback', () => {
  const rejected = [
    'https://evil.com',
    'https://cgcom.stg.eudistack.net.evil.com',
    'https://a.b.stg.eudistack.net',
    'http://sandbox.stg.eudistack.net',
    'https://sandbox.stg.eudistack.net:8443',
    'https://sandbox.stg.eudistack.net/path',
    'https://sandbox_x.stg.eudistack.net',
    "x';alert(1)//",
  ];
  for (const candidate of rejected) {
    assert.equal(STG.resolveTrustedOrigin(candidate), 'https://cgcom.stg.eudistack.net', candidate);
  }
  assert.equal(LOCAL.resolveTrustedOrigin('https://sandbox.127.0.0.1.nip.io'), 'https://cgcom.127.0.0.1.nip.io:4443');
});

test('sin dominio padre (localhost) no admite subdominios', () => {
  assert.equal(STANDALONE.resolveTrustedOrigin('http://evil.localhost:3000'), 'http://localhost:3000');
});

test('guard fija frame-ancestors desde la configuración, nunca desde el origin recibido', () => {
  const res = fakeResponse();
  const origin = STG.guard(res, 'https://evil.com');

  assert.equal(origin, 'https://cgcom.stg.eudistack.net');
  assert.equal(
    res.headers['Content-Security-Policy'],
    'frame-ancestors https://cgcom.stg.eudistack.net https://*.stg.eudistack.net',
  );
});

test('guard desactiva caché y MIME sniffing en las respuestas con datos del certificado', () => {
  const res = fakeResponse();
  STG.guard(res, 'https://cgcom.stg.eudistack.net');

  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(res.headers['X-Content-Type-Options'], 'nosniff');
});

test('guard respeta el fallback, los orígenes extra y el puerto en el comodín de tenant', () => {
  const res = fakeResponse();
  const origin = LOCAL.guard(res, undefined, 'https://landing.example');

  assert.equal(origin, 'https://landing.example');
  assert.equal(
    res.headers['Content-Security-Policy'],
    'frame-ancestors https://cgcom.127.0.0.1.nip.io:4443 http://localhost:3001 https://*.127.0.0.1.nip.io:4443',
  );
});

test('sin dominio padre frame-ancestors solo lista los orígenes conocidos', () => {
  const res = fakeResponse();
  STANDALONE.guard(res, 'http://localhost:3443');

  assert.equal(res.headers['Content-Security-Policy'], 'frame-ancestors http://localhost:3000 http://localhost:3443');
});

test('parseOriginList separa por comas e ignora vacíos', () => {
  assert.deepEqual(parseOriginList(undefined), []);
  assert.deepEqual(parseOriginList(''), []);
  assert.deepEqual(parseOriginList(' http://localhost:3001 , ,https://a.example'), ['http://localhost:3001', 'https://a.example']);
});
