import type { Artifact, CaptureKey, CaptureRequest, Response as CaptureResponse } from './binding';

export * from './binding';

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
