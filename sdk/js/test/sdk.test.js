'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { CaptureKey, Client, Notary, createFetch, verify } = require('..');

// The public key of secp256k1 secret key 1, a valid SEC1 point.
const NOTARY_KEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

test('capture keys are exactly 32 bytes', () => {
  const key = CaptureKey.generate();
  assert.equal(key.toBytes().length, 32);
  assert.deepEqual(CaptureKey.fromBytes(key.toBytes()).toBytes(), key.toBytes());
  assert.throws(() => CaptureKey.fromBytes(Buffer.alloc(31)));
});

test('notary configuration is validated', () => {
  new Notary('tls://notary.example:443', NOTARY_KEY);
  assert.throws(() => new Notary('https://notary.example', NOTARY_KEY));
  assert.throws(() => new Notary('tls://notary.example:443', 'not-a-key'));
});

test('only POST to a fixed provider is sent', async () => {
  const client = new Client(new Notary('tls://notary.example:443', NOTARY_KEY));
  for (const [method, url] of [
    ['GET', 'https://api.openai.com/v1/models'],
    ['POST', 'https://example.com/v1/responses'],
  ]) {
    await assert.rejects(client.witness({ method, url, headers: [], body: Buffer.from('{}') }), (error) => {
      assert.equal(error.code, 'not_capturable');
      assert.match(error.message, /^this request can't be captured: /);
      return true;
    });
  }
});

test('a notary that cannot be reached is unavailable', async () => {
  // Nothing listens on port 1 of the loopback address.
  const client = new Client(new Notary('tcp://127.0.0.1:1', NOTARY_KEY));
  const request = { method: 'POST', url: 'https://api.openai.com/v1/responses', headers: [], body: Buffer.from('{}') };
  await assert.rejects(client.witness(request), { code: 'unavailable' });
  await assert.rejects(client.capture(request, CaptureKey.generate()), { code: 'unavailable' });
});

test('an ES module can import every export by name', async () => {
  const esm = await import('../index.js');
  for (const name of ['CaptureKey', 'Client', 'Notary', 'createFetch', 'exaltoNotary', 'verify']) {
    assert.equal(typeof esm[name], 'function', name);
    assert.equal(esm[name], esm.default[name], name);
  }
});

test('verify rejects bytes that are not a trace', async () => {
  await assert.rejects(verify(Buffer.from('not a trace'), NOTARY_KEY));
});

function fakeClient(status, chunks, { artifact = 'artifact', headersAfter } = {}) {
  const sent = [];
  let artifactsTaken = 0;
  let closed = 0;
  const response = async () => {
    if (headersAfter) await headersAfter;
    const remaining = chunks.map((chunk) => Buffer.from(chunk));
    return {
      status,
      traceId: 'trc-1',
      headers: [['content-type', 'text/event-stream']],
      nextChunk: async () => remaining.shift() ?? null,
      artifact: async () => {
        artifactsTaken += 1;
        if (artifact instanceof Error) throw artifact;
        return artifact;
      },
      close: async () => {
        closed += 1;
      },
    };
  };
  return {
    sent,
    artifactsTaken: () => artifactsTaken,
    closed: () => closed,
    witness: async (request) => {
      sent.push(['witness', request]);
      return response();
    },
    capture: async (request, key) => {
      sent.push(['capture', request, key]);
      return response();
    },
  };
}

test('createFetch streams the body, then hands over the artifact', async () => {
  const client = fakeClient(200, ['data: 1\n\n', 'data: 2\n\n']);
  const artifacts = [];
  const captureFetch = createFetch(client, { mode: 'witnessed', onArtifact: (a) => artifacts.push(a) });
  const response = await captureFetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': 'secret' },
    body: '{"stream":true}',
  });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'data: 1\n\ndata: 2\n\n');
  assert.deepEqual(artifacts, ['artifact']);
  const [kind, request] = client.sent[0];
  assert.equal(kind, 'witness');
  assert.equal(request.method, 'POST');
  assert.equal(request.url, 'https://api.anthropic.com/v1/messages');
  assert.deepEqual(request.headers.find(([name]) => name === 'x-api-key'), ['x-api-key', 'secret']);
  assert.equal(request.body.toString(), '{"stream":true}');
});

test('a provider error passes through unsealed', async () => {
  const client = fakeClient(429, ['{"error":"rate"}']);
  const artifacts = [];
  const captureFetch = createFetch(client, { mode: 'witnessed', onArtifact: (a) => artifacts.push(a) });
  const response = await captureFetch('https://api.openai.com/v1/responses', { method: 'POST', body: '{}' });
  assert.equal(response.status, 429);
  assert.equal(await response.text(), '{"error":"rate"}');
  assert.deepEqual(artifacts, []);
  assert.equal(client.artifactsTaken(), 0);
});

test('notarized needs a key and witnessed takes none', async () => {
  const client = fakeClient(200, []);
  assert.throws(() => createFetch(client, { mode: 'notarized', onArtifact() {} }));
  assert.throws(() => createFetch(client, { mode: 'witnessed', key: CaptureKey.generate(), onArtifact() {} }));
  const key = CaptureKey.generate();
  const captureFetch = createFetch(client, { mode: 'notarized', key, onArtifact() {} });
  await (await captureFetch('https://api.openai.com/v1/responses', { method: 'POST', body: '{}' })).text();
  assert.equal(client.sent[0][0], 'capture');
  assert.equal(client.sent[0][2], key);
});

test('an artifact failure never fails the model call', async () => {
  const client = fakeClient(200, ['{}'], { artifact: new Error('no receipt') });
  const errors = [];
  const captureFetch = createFetch(client, {
    mode: 'witnessed',
    onArtifact() {},
    onError: (error) => errors.push(error.message),
  });
  const response = await captureFetch('https://api.openai.com/v1/responses', { method: 'POST', body: '{}' });
  assert.equal(await response.text(), '{}');
  assert.deepEqual(errors, ['no receipt']);

  const failing = createFetch(fakeClient(200, ['{}']), {
    mode: 'witnessed',
    onArtifact() {
      throw new Error('bucket unavailable');
    },
    onError: (error) => errors.push(error.message),
  });
  await (await failing('https://api.openai.com/v1/responses', { method: 'POST', body: '{}' })).text();
  assert.deepEqual(errors, ['no receipt', 'bucket unavailable']);
});

test('cancelling the body releases the response', async () => {
  const client = fakeClient(200, ['a', 'b']);
  const artifacts = [];
  const captureFetch = createFetch(client, { mode: 'witnessed', onArtifact: (a) => artifacts.push(a) });
  const response = await captureFetch('https://api.openai.com/v1/responses', { method: 'POST', body: '{}' });
  const reader = response.body.getReader();
  await reader.read();
  await reader.cancel();
  assert.equal(client.closed(), 1);
  assert.deepEqual(artifacts, []);
});

test('aborting the signal rejects and releases a late response', async () => {
  let arrive;
  const headersAfter = new Promise((resolve) => {
    arrive = resolve;
  });
  const client = fakeClient(200, ['a'], { headersAfter });
  const captureFetch = createFetch(client, { mode: 'witnessed', onArtifact() {} });
  const controller = new AbortController();
  const pending = captureFetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    body: '{}',
    signal: controller.signal,
  });
  controller.abort();
  await assert.rejects(pending, { name: 'AbortError' });
  arrive();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(client.closed(), 1);
});
