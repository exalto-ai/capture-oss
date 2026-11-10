'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');

const native = require('./binding.js');

const SEALABLE = (status) => status >= 200 && status < 300;
const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

const CODE_TAG = /^\[(not_capturable|allowance_exhausted|unauthorized|unavailable)\] /;

/** Moves the binding's code tag from the start of `error.message` to `error.code`. */
function coded(error) {
  const tag = error instanceof Error ? CODE_TAG.exec(error.message) : null;
  if (tag) {
    error.message = error.message.slice(tag[0].length);
    if (typeof error.stack === 'string') error.stack = error.stack.replace(tag[0], '');
    error.code = tag[1];
  }
  return error;
}

function rethrowCoded(error) {
  throw coded(error);
}

for (const name of ['witness', 'capture', 'notarize']) {
  const call = native.Client.prototype[name];
  native.Client.prototype[name] = function (...args) {
    return call.apply(this, args).catch(rethrowCoded);
  };
}

/** Exalto's notary, found through Exalto's Registry. */
function exaltoNotary(apiKey, apiOrigin) {
  return native.exaltoNotary(apiKey, apiOrigin).catch(rethrowCoded);
}

const contextStorage = new AsyncLocalStorage();

/**
 * Runs `fn`, handing `fields` to `onArtifact`, as `artifact.context`, with the
 * artifact of every request sent while it runs. Nested calls merge, the inner
 * one winning. The fields are read when a request is sent and stay in your
 * process: they are never sent anywhere or written into the evidence.
 */
function captureContext(fields, fn) {
  return contextStorage.run({ ...contextStorage.getStore(), ...fields }, fn);
}

function logError(error) {
  console.error('Exalto Capture produced no artifact for a provider response:', error?.message ?? error);
}

/** Settles with `promise`, or rejects when `signal` aborts first; a late result is passed to `onLate`. */
function abortable(promise, signal, onLate) {
  return new Promise((resolve, reject) => {
    const abort = () => {
      reject(signal.reason);
      promise.then(onLate, () => {});
    };
    if (signal.aborted) {
      abort();
      return;
    }
    signal.addEventListener('abort', abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', abort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', abort);
        reject(error);
      },
    );
  });
}

/**
 * A `fetch` that sends every request through `client` in `mode`. Pass it as the
 * `fetch` option of an OpenAI or Anthropic client. `onArtifact` receives each
 * Artifact once its response body has been read to the end. A provider error
 * response is passed through but never sealed, and a body that is never read
 * produces no artifact.
 *
 * The provider has already answered by the time an artifact is ready, so a
 * failure to produce or keep one never fails the model call. It goes to
 * `onError`, which logs it by default. Aborting the request's signal, or
 * cancelling its body, releases the provider connection and notary session.
 *
 * `shouldCapture` picks which requests to capture. A request it declines goes
 * to the provider through `forward` instead, by default the global `fetch`,
 * unrecorded, as it would without the SDK. The choice is made before anything
 * is sent: a request this fetch tries to capture and can't is never sent
 * unrecorded.
 */
function createFetch(client, options) {
  const { mode, key, onArtifact, onError = logError, shouldCapture, forward = globalThis.fetch } = options ?? {};
  if (mode === 'witnessed') {
    if (key !== undefined) throw new TypeError('Witnessed capture produces a Sealed trace and takes no key');
  } else if (mode === 'notarized') {
    if (key === undefined) throw new TypeError('Notarized capture needs the CaptureKey that encrypts its .llmcapture');
  } else {
    throw new TypeError('mode must be "witnessed" or "notarized"');
  }
  if (typeof onArtifact !== 'function') throw new TypeError('onArtifact must be a function');
  if (typeof onError !== 'function') throw new TypeError('onError must be a function');
  if (shouldCapture !== undefined && typeof shouldCapture !== 'function') {
    throw new TypeError('shouldCapture must be a function');
  }
  if (typeof forward !== 'function') throw new TypeError('forward must be a function');

  return async function captureFetch(input, init) {
    const context = { ...contextStorage.getStore() };
    const request = new Request(input, init);
    const { signal } = request;
    signal.throwIfAborted();
    if (shouldCapture && !shouldCapture(request)) return forward(request);
    const call = {
      method: request.method,
      url: request.url,
      headers: [...request.headers],
      body: Buffer.from(await request.arrayBuffer()),
    };
    const pending = mode === 'witnessed' ? client.witness(call) : client.capture(call, key);
    const response = await abortable(pending, signal, (late) => late.close().catch(() => {}));

    let open = true;
    const release = () => {
      if (!open) return;
      open = false;
      response.close().catch(() => {});
    };
    if (NULL_BODY_STATUSES.has(response.status)) {
      release();
      return new Response(null, { status: response.status, headers: response.headers });
    }
    let onAbort;
    const body = new ReadableStream({
      start(controller) {
        onAbort = () => {
          controller.error(signal.reason);
          release();
        };
        signal.addEventListener('abort', onAbort, { once: true });
      },
      async pull(controller) {
        try {
          const chunk = await response.nextChunk();
          if (chunk) {
            controller.enqueue(new Uint8Array(chunk));
            return;
          }
          signal.removeEventListener('abort', onAbort);
          open = false;
          if (SEALABLE(response.status)) {
            try {
              await onArtifact({ ...(await response.artifact()), context });
            } catch (error) {
              try {
                await onError(error);
              } catch {
                // A failing error handler must not fail the model call either.
              }
            }
          }
          controller.close();
        } catch (error) {
          signal.removeEventListener('abort', onAbort);
          controller.error(error);
          release();
        }
      },
      cancel() {
        signal.removeEventListener('abort', onAbort);
        release();
      },
    });
    return new Response(body, { status: response.status, headers: response.headers });
  };
}

// Spreading `require(...)` directly, rather than a variable holding it, is what
// lets Node's ESM loader see the binding's names, so that
// `import { Client } from '@exalto/capture'` works as well as the default import.
module.exports = { ...require('./binding.js'), exaltoNotary, createFetch, captureContext };
