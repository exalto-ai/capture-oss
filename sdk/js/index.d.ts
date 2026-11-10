import type { Artifact, CaptureKey, CaptureRequest, Response as CaptureResponse } from './binding';

export * from './binding';

/**
 * The `code` of an error from `witness`, `capture`, `notarize` or
 * `exaltoNotary`, for the failures a caller can act on; any other failure has
 * none of these. A `witness` or `capture` that fails with one sent nothing to
 * the provider.
 *
 * - `not_capturable`: not a `POST` to a supported provider path, or too large to attest.
 * - `allowance_exhausted`: the organization's allowance or plan doesn't cover the session.
 * - `unauthorized`: Exalto refused the API key: unknown, revoked, or without the scope needed.
 * - `unavailable`: Exalto's API or the notary couldn't be reached; trying again later may work.
 */
export type CaptureErrorCode = 'not_capturable' | 'allowance_exhausted' | 'unauthorized' | 'unavailable';

/** The part of `Client` that `createFetch` uses. */
export interface CaptureClient {
  witness(request: CaptureRequest): Promise<CaptureResponse>;
  capture(request: CaptureRequest, key: CaptureKey): Promise<CaptureResponse>;
}

type ArtifactHandlers = {
  onArtifact: (artifact: Artifact) => unknown;
  /** Receives a failure to produce or keep an artifact; logs it by default. */
  onError?: (error: unknown) => unknown;
};

export type CreateFetchOptions =
  | ({ mode: 'witnessed'; key?: undefined } & ArtifactHandlers)
  | ({ mode: 'notarized'; key: CaptureKey } & ArtifactHandlers);

/**
 * A `fetch` that sends every request through `client` in `mode`. Pass it as the
 * `fetch` option of an OpenAI or Anthropic client. `onArtifact` receives each
 * Artifact once its response body has been read to the end. A provider error
 * response is passed through but never sealed, and a body that is never read
 * produces no artifact. A failure to produce or keep an artifact never fails
 * the model call; it goes to `onError`. Aborting the request's signal, or
 * cancelling its body, releases the provider connection and notary session.
 */
export function createFetch(client: CaptureClient, options: CreateFetchOptions): typeof fetch;
