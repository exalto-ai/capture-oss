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

/** An artifact as `createFetch` hands it over, with its request's `captureContext` fields. */
export type CapturedArtifact = Artifact & { context: Record<string, unknown> };

type ArtifactHandlers = {
  onArtifact: (artifact: CapturedArtifact) => unknown;
  /** Receives a failure to produce or keep an artifact; logs it by default. */
  onError?: (error: unknown) => unknown;
  /**
   * Whether to capture `request`; don't read its body. A request it declines
   * goes to the provider through `forward`, unrecorded. Without it, every
   * request is captured.
   */
  shouldCapture?: (request: Request) => boolean;
  /** Sends the requests `shouldCapture` declines; the global `fetch` by default. */
  forward?: typeof fetch;
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
 * A request `shouldCapture` declines goes through `forward`, unrecorded; a
 * request this fetch tries to capture and can't is never sent unrecorded.
 */
export function createFetch(client: CaptureClient, options: CreateFetchOptions): typeof fetch;

/**
 * Runs `fn`, handing `fields` to `onArtifact`, as `artifact.context`, with the
 * artifact of every request sent while it runs. Nested calls merge, the inner
 * one winning. The fields stay in your process: they are never sent anywhere
 * or written into the evidence.
 */
export function captureContext<T>(fields: Record<string, unknown>, fn: () => T): T;
