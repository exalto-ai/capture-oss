import type {
  AccountConnection,
  CaptureMode,
  Event,
  LocalApi,
  Notaries,
  Operation,
  Share,
  ShareVisibility,
  Status,
  TraceContent,
  TraceDetail,
  TraceSummary,
  Verification,
} from './api';
import { LocalApiError } from './api';

const hour = 60 * 60 * 1000;
const fixtureNow = Date.UTC(2026, 6, 28, 16, 42, 0);

type FixtureShareState = {
  captureId: string;
  progress: 'verifying' | 'shared' | 'stopped' | 'rejected' | 'failed';
  visibility: ShareVisibility;
  accessEnabled: boolean;
  passwordProtected: boolean;
  expiresAt: number | null;
  failureCode: string | null;
  updatedAt: number;
};

const proofProgress = (
  bytesCompleted: number,
  bytesTotal: number,
  commitmentsCompleted: number,
  commitmentsTotal: number,
  updatedAt: number,
) => ({
  phase: 'proving',
  updated_at_unix_ms: updatedAt,
  proof: {
    bytes_completed: bytesCompleted,
    bytes_total: bytesTotal,
    commitments_completed: commitmentsCompleted,
    commitments_total: commitmentsTotal,
  },
});

export const fixtureCaptures: TraceSummary[] = [
  {
    trace_id: 'trc-20260728-knowledge-eval',
    created_at_unix_ms: fixtureNow - hour * 2,
    completed_at_unix_ms: fixtureNow - hour * 2 + 1842,
    provider: 'openai',
    operation: '/v1/responses',
    requested_model: 'gpt-5.2',
    response_model: 'gpt-5.2',
    http_status: 200,
    streaming: true,
    request_bytes: 1842,
    response_bytes: 9421,
    duration_ms: 1842,
    state: 'captured',
    status: null,
    notarization_eligible: true,
    evidence_kind: 'notarized',
    prompt_preview:
      'Compare two sanitized evaluation strategies and identify the stronger evidence trail.',
    prompt_preview_truncated: false,
    output_preview:
      'The second strategy preserves a clearer chain of independently checkable claims…',
    output_preview_truncated: true,
  },
  {
    trace_id: 'trc-20260728-safety-review',
    created_at_unix_ms: fixtureNow - hour * 4,
    completed_at_unix_ms: fixtureNow - hour * 4 + 967,
    provider: 'anthropic',
    operation: '/v1/messages',
    requested_model: 'claude-sonnet-4-6',
    response_model: 'claude-sonnet-4-6',
    http_status: 200,
    streaming: false,
    request_bytes: 1210,
    response_bytes: 5110,
    duration_ms: 967,
    state: 'captured',
    status: 'notarizing',
    notarization_eligible: true,
    evidence_kind: 'notarized',
    prompt_preview: 'Review a synthetic policy response for unsupported claims.',
    prompt_preview_truncated: false,
    output_preview: 'Three claims require either a citation or more qualified language.',
    output_preview_truncated: false,
  },
  {
    trace_id: 'trc-20260727-research-brief',
    created_at_unix_ms: fixtureNow - hour * 18,
    completed_at_unix_ms: fixtureNow - hour * 18 + 2312,
    provider: 'openrouter',
    operation: '/api/v1/chat/completions',
    requested_model: 'openai/gpt-5-mini',
    response_model: 'openai/gpt-5-mini',
    http_status: 200,
    streaming: true,
    request_bytes: 2208,
    response_bytes: 14392,
    duration_ms: 2312,
    state: 'notarized',
    status: null,
    notarization_eligible: true,
    evidence_kind: 'notarized',
    prompt_preview:
      'Choose a reproducibility baseline from two sanitized evaluation runs and explain the limits of the evidence.',
    prompt_preview_truncated: false,
    output_preview:
      'Use Run 15 as the baseline; its settings were recorded and all 20 reruns matched.',
    output_preview_truncated: false,
  },
  {
    trace_id: 'trc-20260726-direct-link',
    created_at_unix_ms: fixtureNow - hour * 31,
    completed_at_unix_ms: fixtureNow - hour * 31 + 1288,
    provider: 'anthropic',
    operation: '/v1/messages',
    requested_model: 'claude-sonnet-4-6',
    response_model: 'claude-sonnet-4-6',
    http_status: 200,
    streaming: false,
    request_bytes: 1540,
    response_bytes: 7290,
    duration_ms: 1288,
    state: 'notarized',
    status: null,
    notarization_eligible: true,
    evidence_kind: 'notarized',
    prompt_preview: 'Check whether the direct-link fixture keeps its provider and model identity.',
    prompt_preview_truncated: false,
    output_preview: 'The fixture identity remains Anthropic / claude-sonnet-4-6 in every view.',
    output_preview_truncated: false,
  },
  {
    trace_id: 'trc-20260727-benchmark',
    created_at_unix_ms: fixtureNow - hour * 25,
    completed_at_unix_ms: fixtureNow - hour * 25 + 1400,
    provider: 'deepseek',
    operation: '/chat/completions',
    requested_model: 'deepseek-v4-flash',
    response_model: 'deepseek-v4-flash',
    http_status: 200,
    streaming: false,
    request_bytes: 3101,
    response_bytes: 8802,
    duration_ms: 1400,
    state: 'captured',
    status: 'notarization_failed',
    notarization_eligible: true,
    evidence_kind: 'notarized',
    prompt_preview: 'Run the deterministic benchmark fixture.',
    prompt_preview_truncated: false,
    output_preview: 'Benchmark fixture complete.',
    output_preview_truncated: false,
    failure_code: 'notary_capacity',
  },
  {
    trace_id: 'trc-20260728-auth-error',
    created_at_unix_ms: fixtureNow - hour * 6,
    completed_at_unix_ms: fixtureNow - hour * 6 + 412,
    provider: 'openai',
    operation: '/v1/responses',
    requested_model: 'gpt-5.2',
    response_model: null,
    http_status: 401,
    streaming: true,
    request_bytes: 988,
    response_bytes: 214,
    duration_ms: 412,
    state: 'captured',
    status: null,
    notarization_eligible: false,
    evidence_kind: 'notarized',
    notarization_ineligibility_code: 'unsupported_provider_http_status',
    prompt_preview: 'Summarize the sanitized authentication-error fixture.',
    prompt_preview_truncated: false,
    output_preview: '',
    output_preview_truncated: false,
  },
  {
    trace_id: 'trc-20260728-active',
    created_at_unix_ms: fixtureNow - 42_000,
    provider: 'openai',
    operation: '/v1/responses',
    requested_model: 'gpt-5.2-mini',
    streaming: true,
    request_bytes: 720,
    state: null,
    status: 'capturing',
    notarization_eligible: false,
    evidence_kind: 'notarized',
    prompt_preview: 'Create a sanitized fixture summary.',
    prompt_preview_truncated: false,
    output_preview: '',
    output_preview_truncated: false,
  },
];

export const fixtureOperations: Operation[] = [
  {
    operation_id: 'op-notarize-safety-review',
    kind: 'notarization',
    trace_id: 'trc-20260728-safety-review',
    state: 'running',
    attempt: 1,
    created_at_unix_ms: fixtureNow - 112_000,
    started_at_unix_ms: fixtureNow - 108_000,
    progress: proofProgress(612_352, 1_284_096, 4, 10, fixtureNow - 28_000),
    retryable: false,
    attempt_history: [{ attempt: 1, state: 'running', started_at_unix_ms: fixtureNow - 108_000 }],
  },
  {
    operation_id: 'op-notarize-benchmark',
    kind: 'notarization',
    trace_id: 'trc-20260727-benchmark',
    state: 'failed',
    attempt: 2,
    created_at_unix_ms: fixtureNow - hour,
    started_at_unix_ms: fixtureNow - hour + 2_000,
    completed_at_unix_ms: fixtureNow - hour + 18_000,
    failure_code: 'notary_capacity',
    progress: proofProgress(262_144, 731_480, 2, 6, fixtureNow - hour + 17_000),
    retryable: true,
    attempt_history: [
      {
        attempt: 2,
        state: 'failed',
        started_at_unix_ms: fixtureNow - hour + 2_000,
        completed_at_unix_ms: fixtureNow - hour + 18_000,
        failure_code: 'notary_capacity',
      },
      {
        attempt: 1,
        state: 'interrupted',
        started_at_unix_ms: fixtureNow - hour * 2,
        completed_at_unix_ms: fixtureNow - hour * 2 + 9_000,
        failure_code: 'service_restarted',
      },
    ],
  },
  {
    operation_id: 'op-notarize-research-brief',
    kind: 'notarization',
    trace_id: 'trc-20260727-research-brief',
    state: 'succeeded',
    attempt: 1,
    created_at_unix_ms: fixtureNow - hour * 17,
    started_at_unix_ms: fixtureNow - hour * 17 + 1_000,
    completed_at_unix_ms: fixtureNow - hour * 17 + 184_000,
    progress: {
      phase: 'complete',
      updated_at_unix_ms: fixtureNow - hour * 17 + 184_000,
      proof: {
        bytes_completed: 1_934_120,
        bytes_total: 1_934_120,
        commitments_completed: 16,
        commitments_total: 16,
      },
    },
    retryable: false,
    attempt_history: [
      {
        attempt: 1,
        state: 'succeeded',
        started_at_unix_ms: fixtureNow - hour * 17 + 1_000,
        completed_at_unix_ms: fixtureNow - hour * 17 + 184_000,
      },
    ],
  },
  {
    operation_id: 'op-notarize-direct-link',
    kind: 'notarization',
    trace_id: 'trc-20260726-direct-link',
    state: 'succeeded',
    attempt: 1,
    created_at_unix_ms: fixtureNow - hour * 30,
    started_at_unix_ms: fixtureNow - hour * 30 + 1_000,
    completed_at_unix_ms: fixtureNow - hour * 30 + 161_000,
    retryable: false,
    progress: {
      phase: 'complete',
      updated_at_unix_ms: fixtureNow - hour * 30 + 161_000,
      proof: {
        bytes_completed: 1_224_930,
        bytes_total: 1_224_930,
        commitments_completed: 10,
        commitments_total: 10,
      },
    },
    attempt_history: [
      {
        attempt: 1,
        state: 'succeeded',
        started_at_unix_ms: fixtureNow - hour * 30 + 1_000,
        completed_at_unix_ms: fixtureNow - hour * 30 + 161_000,
      },
    ],
  },
];

export const fixtureEvents: Event[] = [
  {
    event_id: 14,
    created_at_unix_ms: fixtureNow - 28_000,
    event_type: 'notarization_started',
    trace_id: 'trc-20260728-safety-review',
    operation_id: 'op-notarize-safety-review',
    severity: 'info',
    message: 'Sealing started',
  },
  {
    event_id: 13,
    created_at_unix_ms: fixtureNow - hour,
    event_type: 'notarization_failed',
    trace_id: 'trc-20260727-benchmark',
    operation_id: 'op-notarize-benchmark',
    severity: 'error',
    message: 'Sealing failed',
    safe_code: 'notary_capacity',
  },
  {
    event_id: 12,
    created_at_unix_ms: fixtureNow - hour * 17,
    event_type: 'notarization_completed',
    trace_id: 'trc-20260727-research-brief',
    operation_id: 'op-notarize-research-brief',
    severity: 'success',
    message: 'Sealing completed',
  },
  {
    event_id: 11,
    created_at_unix_ms: fixtureNow - hour * 30,
    event_type: 'notarization_completed',
    trace_id: 'trc-20260726-direct-link',
    operation_id: 'op-notarize-direct-link',
    severity: 'success',
    message: 'Sealing completed',
  },
];

const captureModeEvents: Record<CaptureMode, [string, string]> = {
  off: ['capture_disabled', 'Capture requests disabled'],
  witnessed: ['capture_witnessed', 'Witnessed capture enabled'],
  notarized: ['capture_notarized', 'Notarized capture enabled'],
};

export const fixtureStatus: Status = {
  version: '0.1.0',
  build_id: 'dev',
  runtime_profile: 'local',
  lifecycle: 'ready',
  capture_mode: 'notarized',
  proxy_listener: '127.0.0.1:8787',
  admin_listener: '127.0.0.1:8788',
  proxy_origin: 'http://127.0.0.1:8787',
  admin_origin: 'http://127.0.0.1:8788',
  metadata_backend: 'sqlite',
  metadata_status: 'ready',
  artifact_backend: 'filesystem',
  artifact_status: 'ready',
  vault: 'OS vault',
  notary: 'registry',
  preview_chars: 1000,
  counts: {
    captured: 3,
    notarizing: 1,
    notarized: 2,
    needs_attention: 1,
    capturing: 1,
    capture_failed: 0,
  },
  updates: {
    enabled: false,
    current_build_id: 'dev',
    latest_build_id: null,
    update_available: false,
    last_checked_unix_ms: null,
    error_code: null,
  },
};

export const fixtureNotaries: Notaries = {
  source: 'registry',
  registry_source: 'https://api.capture.exalto.ai/api/registry',
  generation: 12,
  active_key_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  notaries: [
    {
      name: 'Seal',
      operator: 'Exalto',
      endpoint: 'tls://notary.capture.exalto.ai:443',
      transport: 'tls',
      key_id: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      verification_key: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      lifecycle: 'active',
      valid_from_unix_ms: fixtureNow - hour * 24 * 30,
      valid_until_unix_ms: null,
      notarize_until_unix_ms: null,
    },
    {
      name: 'seal1',
      operator: 'Exalto',
      endpoint: 'tls://notary-old.exalto.ai:7047',
      transport: 'tls',
      key_id: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      verification_key: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      lifecycle: 'retiring',
      valid_from_unix_ms: fixtureNow - hour * 24 * 120,
      valid_until_unix_ms: fixtureNow - hour * 24 * 7,
      notarize_until_unix_ms: fixtureNow + hour * 24 * 14,
    },
    {
      name: 'seal2',
      operator: 'Exalto',
      endpoint: 'tls://notary-history.exalto.ai:7047',
      transport: 'tls',
      key_id: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      verification_key: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      lifecycle: 'retired',
      valid_from_unix_ms: fixtureNow - hour * 24 * 240,
      valid_until_unix_ms: fixtureNow - hour * 24 * 121,
      notarize_until_unix_ms: fixtureNow - hour * 24 * 90,
    },
    {
      name: 'seal3',
      operator: 'Exalto',
      endpoint: 'tls://notary-revoked.exalto.ai:7047',
      transport: 'tls',
      key_id: 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      verification_key: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      lifecycle: 'revoked',
      valid_from_unix_ms: fixtureNow - hour * 24 * 360,
      valid_until_unix_ms: fixtureNow - hour * 24 * 241,
      notarize_until_unix_ms: fixtureNow - hour * 24 * 220,
    },
  ],
};

const fixtureTrace: TraceContent = {
  trace_id: 'trc-20260727-research-brief',
  manifest: {
    format: 'ecp/trace-package/v1',
    normalizer_version: 'ecp/normalizer/v1',
    trace_sha256: '9a32d7c66a7e4fdd525ea6c803355273ade0f46e7c8dc4973343399731585b26',
    source: {
      provider: { name: 'openrouter', host: 'openrouter.ai' },
      created_at_unix_ms: fixtureNow - hour * 18,
    },
  },
  trace: {
    resourceSpans: [
      {
        scopeSpans: [
          {
            spans: [
              {
                name: 'gen_ai.inference',
                traceId: '31f90c419f264b70b09fb1baf4f567d0',
                attributes: [
                  { key: 'gen_ai.provider.name', value: { stringValue: 'openrouter' } },
                  { key: 'gen_ai.operation.name', value: { stringValue: 'chat' } },
                  { key: 'gen_ai.request.model', value: { stringValue: 'openai/gpt-5-mini' } },
                  { key: 'gen_ai.response.model', value: { stringValue: 'openai/gpt-5-mini' } },
                  { key: 'server.address', value: { stringValue: 'openrouter.ai' } },
                  { key: 'gen_ai.usage.input_tokens', value: { intValue: '184' } },
                  { key: 'gen_ai.usage.output_tokens', value: { intValue: '126' } },
                  {
                    key: 'gen_ai.input.messages',
                    value: {
                      stringValue: JSON.stringify([
                        {
                          role: 'system',
                          parts: [
                            {
                              type: 'text',
                              content:
                                'Write a short research note. Preserve source labels and flag conclusions that go beyond the notes.',
                            },
                          ],
                        },
                        {
                          role: 'user',
                          parts: [
                            {
                              type: 'text',
                              content:
                                'Choose a reproducibility baseline from these sanitized evaluation notes.\n\nRun 14 (Source A): The model version was pinned, but temperature was omitted. A 20-case rerun produced three different answers.\nRun 15 (Source B): The model version and temperature=0 were pinned. A 20-case rerun matched every answer.\nArchive check (Source C): The stored response SHA-256 matched the bytes downloaded from the provider.',
                            },
                          ],
                        },
                      ]),
                    },
                  },
                  {
                    key: 'gen_ai.output.messages',
                    value: {
                      stringValue: JSON.stringify([
                        {
                          role: 'assistant',
                          finish_reason: 'stop',
                          parts: [
                            {
                              type: 'text',
                              content:
                                'Use Run 15 as the reproducibility baseline. It records both the model version and temperature, and its 20-case rerun matched exactly (Source B).\n\nRun 14 is weaker because the missing temperature leaves a plausible explanation for its three mismatches (Source A). The notes do not prove that temperature caused them.\n\nThe archive check confirms that the retained response matches the downloaded provider bytes (Source C). It does not establish that the response is factually correct.',
                            },
                          ],
                        },
                      ]),
                    },
                  },
                ],
              },
            ],
          },
        ],
      },
    ],
  },
};

const fixtureVerification: Verification = {
  trace_id: fixtureTrace.trace_id,
  outcome: 'passed',
  verified_at_unix_ms: fixtureNow,
  notary_key_id: 'sha256:3828b21f26c49a0ff546f6f4bcee6a64bdc685faf4a961b3c00d05814cda9801',
  trust_source: 'registry',
};

function detail(
  captureId: string,
  captures: TraceSummary[],
  operations: Operation[],
  share: Share | null = null,
): TraceDetail {
  const capture = captures.find((item) => item.trace_id === captureId);
  if (!capture) throw new LocalApiError(404, 'capture_not_found', 'Trace not found');
  return {
    ...capture,
    artifacts: [
      {
        kind: 'capture_checkpoint',
        size_bytes: 189_442,
        sha256: deterministicHex(`${capture.trace_id}:bundle`, 64),
      },
      ...(capture.state === 'notarized'
        ? [
            {
              kind: 'trace_package',
              size_bytes: 482_013,
              sha256: deterministicHex(`${capture.trace_id}:package`, 64),
            },
          ]
        : []),
    ],
    notarization: operations.find((operation) => operation.trace_id === capture.trace_id) ?? null,
    share,
  };
}

function shiftCapture(capture: TraceSummary, offset: number): TraceSummary {
  return {
    ...capture,
    created_at_unix_ms: capture.created_at_unix_ms + offset,
    completed_at_unix_ms:
      capture.completed_at_unix_ms == null
        ? capture.completed_at_unix_ms
        : capture.completed_at_unix_ms + offset,
  };
}

function shiftOperation(operation: Operation, offset: number): Operation {
  return {
    ...operation,
    created_at_unix_ms: operation.created_at_unix_ms + offset,
    started_at_unix_ms:
      operation.started_at_unix_ms == null
        ? operation.started_at_unix_ms
        : operation.started_at_unix_ms + offset,
    completed_at_unix_ms:
      operation.completed_at_unix_ms == null
        ? operation.completed_at_unix_ms
        : operation.completed_at_unix_ms + offset,
    attempt_history: operation.attempt_history.map((attempt) => ({
      ...attempt,
      started_at_unix_ms:
        attempt.started_at_unix_ms == null
          ? attempt.started_at_unix_ms
          : attempt.started_at_unix_ms + offset,
      completed_at_unix_ms:
        attempt.completed_at_unix_ms == null
          ? attempt.completed_at_unix_ms
          : attempt.completed_at_unix_ms + offset,
    })),
  };
}

const providerHosts: Record<string, string> = {
  anthropic: 'api.anthropic.com',
  deepseek: 'api.deepseek.com',
  openai: 'api.openai.com',
  openrouter: 'openrouter.ai',
};

function deterministicHex(value: string, length: number) {
  let state = 2_166_136_261;
  let output = '';
  while (output.length < length) {
    for (const character of value) {
      state ^= character.charCodeAt(0);
      state = Math.imul(state, 16_777_619);
    }
    output += (state >>> 0).toString(16).padStart(8, '0');
    state ^= output.length;
  }
  return output.slice(0, length);
}

function traceForCapture(capture: TraceSummary): TraceContent {
  const trace = structuredClone(fixtureTrace);
  const manifest = trace.manifest as {
    trace_sha256?: string;
    source?: { provider?: { name?: string; host?: string }; created_at_unix_ms?: number };
  };
  manifest.trace_sha256 = deterministicHex(`${capture.trace_id}:trace-bytes`, 64);
  if (manifest.source) {
    manifest.source.provider = {
      name: capture.provider,
      host: providerHosts[capture.provider] ?? `${capture.provider}.example`,
    };
    manifest.source.created_at_unix_ms = capture.created_at_unix_ms;
  }
  const span = (
    trace.trace as {
      resourceSpans?: Array<{
        scopeSpans?: Array<{
          spans?: Array<{
            traceId?: string;
            spanId?: string;
            attributes?: Array<{ key: string; value: { stringValue?: string } }>;
          }>;
        }>;
      }>;
    }
  ).resourceSpans?.[0]?.scopeSpans?.[0]?.spans?.[0];
  if (span) {
    span.traceId = deterministicHex(`${capture.trace_id}:trace`, 32);
    span.spanId = deterministicHex(`${capture.trace_id}:span`, 16);
    const values: Record<string, string> = {
      'gen_ai.provider.name': capture.provider,
      'gen_ai.operation.name': capture.operation,
      'gen_ai.request.model': capture.requested_model ?? 'Model not reported',
      'gen_ai.response.model':
        capture.response_model ?? capture.requested_model ?? 'Model not reported',
      'server.address': providerHosts[capture.provider] ?? `${capture.provider}.example`,
      'gen_ai.input.messages': JSON.stringify([
        {
          role: 'user',
          parts: [
            {
              type: 'text',
              content: capture.prompt_preview || 'Fixture prompt preview is disabled.',
            },
          ],
        },
      ]),
      'gen_ai.output.messages': JSON.stringify([
        {
          role: 'assistant',
          finish_reason: 'stop',
          parts: [
            {
              type: 'text',
              content: capture.output_preview || 'Fixture response preview is disabled.',
            },
          ],
        },
      ]),
    };
    const preserveDetailedTranscript = capture.trace_id === fixtureTrace.trace_id;
    for (const attribute of span.attributes ?? []) {
      if (
        attribute.key in values &&
        (!preserveDetailedTranscript ||
          !['gen_ai.input.messages', 'gen_ai.output.messages'].includes(attribute.key))
      ) {
        attribute.value.stringValue = values[attribute.key];
      }
    }
  }
  return { ...trace, trace_id: capture.trace_id };
}

export function createFixtureApi({
  nowUnixMs = Date.now(),
  initialShare,
}: {
  nowUnixMs?: number;
  initialShare?: {
    traceId: string;
    visibility: ShareVisibility;
    accessEnabled: boolean;
    passwordProtected?: boolean;
    expiresAt?: number | null;
    progress?: FixtureShareState['progress'];
    failureCode?: string | null;
  };
} = {}): LocalApi {
  const clock = Number.isFinite(nowUnixMs) && nowUnixMs > 0 ? nowUnixMs : Date.now();
  const offset = clock - fixtureNow;
  let captures = fixtureCaptures.map((capture) => shiftCapture(structuredClone(capture), offset));
  let operations = fixtureOperations.map((operation) =>
    shiftOperation(structuredClone(operation), offset),
  );
  let events = fixtureEvents.map((event) => ({
    ...structuredClone(event),
    created_at_unix_ms: event.created_at_unix_ms + offset,
  }));
  const traces = new Map(
    captures
      .filter((capture) => capture.state === 'notarized')
      .map((capture) => [capture.trace_id, traceForCapture(capture)]),
  );
  let account: AccountConnection = {
    signed_in: true,
    connection_state: 'connected',
    provider_display_name: 'sample-user',
    display_name: 'Sample User',
    auth_provider: 'github',
    device_name: 'Admin dashboard',
    credential_kind: 'device_session',
    credential_name: 'Admin dashboard',
    billing: { plan: 'one_gb', billing_status: 'active', purchase_mode: 'test' },
    credits: {
      reset_at: Math.floor((fixtureNow + hour * 24 * 10) / 1000),
      capture: {
        total_granted_bytes: 10_000_000,
        total_used_bytes: 1_000_000,
        total_remaining_bytes: 9_000_000,
        included_monthly_remaining_bytes: 9_000_000,
        supplemental_remaining_bytes: 0,
        next_grant_expiration: null,
      },
      notarization: {
        total_granted_bytes: 10_000_000,
        total_used_bytes: 2_000_000,
        total_remaining_bytes: 8_000_000,
        included_monthly_remaining_bytes: 8_000_000,
        supplemental_remaining_bytes: 0,
        next_grant_expiration: null,
      },
    },
    links: {
      account: 'https://capture.exalto.ai/app/overview',
      usage: 'https://capture.exalto.ai/app/usage',
      plans: 'https://capture.exalto.ai/app/usage',
      settings: 'https://capture.exalto.ai/app/settings',
    },
  };
  let nextEventId = Math.max(...events.map((event) => event.event_id)) + 1;
  let nextActionTime = clock;
  let captureMode = fixtureStatus.capture_mode;
  let autoSealEnabled = false;
  const progressingOperations = new Set<string>();
  const operationPolls = new Map<string, number>();
  const shares = new Map<string, FixtureShareState>();
  if (initialShare) {
    shares.set('share-fixture', {
      captureId: initialShare.traceId,
      progress: initialShare.progress ?? 'shared',
      visibility: initialShare.visibility,
      accessEnabled: initialShare.accessEnabled,
      passwordProtected: initialShare.passwordProtected ?? false,
      expiresAt: initialShare.expiresAt ?? null,
      failureCode: initialShare.failureCode ?? null,
      updatedAt: clock,
    });
  }
  const actionTimestamp = () => {
    nextActionTime += 1000;
    return nextActionTime;
  };
  const recordEvent = (
    eventType: string,
    message: string,
    severity: string,
    captureId?: string,
    operationId?: string,
  ) => {
    events = [
      {
        event_id: nextEventId,
        created_at_unix_ms: actionTimestamp(),
        event_type: eventType,
        trace_id: captureId,
        operation_id: operationId,
        severity,
        message,
      },
      ...events,
    ];
    nextEventId += 1;
  };
  const setCaptureNotarization = (captureId: string, notarizationState: string) => {
    captures = captures.map((capture) =>
      capture.trace_id === captureId
        ? {
            ...capture,
            state: notarizationState === 'succeeded' ? 'notarized' : 'captured',
            status:
              notarizationState === 'queued' || notarizationState === 'running'
                ? 'notarizing'
                : notarizationState === 'failed'
                  ? 'notarization_failed'
                  : notarizationState === 'interrupted'
                    ? 'notarization_interrupted'
                    : null,
          }
        : capture,
    );
  };
  const advanceFixtureOperation = (operationId: string) => {
    if (!progressingOperations.has(operationId)) return;
    const polls = operationPolls.get(operationId) ?? 0;
    operationPolls.set(operationId, polls + 1);
    if (polls === 0) return;
    const operation = operations.find((item) => item.operation_id === operationId);
    if (!operation?.trace_id) {
      progressingOperations.delete(operationId);
      return;
    }
    if (operation.state === 'queued') {
      const attempt = operation.attempt + 1;
      const startedAt = actionTimestamp();
      operations = operations.map((item) =>
        item.operation_id === operationId
          ? {
              ...item,
              state: 'running',
              attempt,
              started_at_unix_ms: startedAt,
              completed_at_unix_ms: null,
              progress: proofProgress(384_000, 1_120_000, 3, 9, startedAt),
              retryable: false,
              attempt_history: [
                { attempt, state: 'running', started_at_unix_ms: startedAt },
                ...item.attempt_history,
              ],
            }
          : item,
      );
      setCaptureNotarization(operation.trace_id, 'running');
      recordEvent(
        'notarization_started',
        'Sealing started',
        'info',
        operation.trace_id,
        operationId,
      );
      return;
    }
    if (operation.state !== 'running') return;
    const completedAt = actionTimestamp();
    operations = operations.map((item) =>
      item.operation_id === operationId
        ? {
            ...item,
            state: 'succeeded',
            completed_at_unix_ms: completedAt,
            progress: {
              ...item.progress,
              phase: 'complete',
              updated_at_unix_ms: completedAt,
              proof: item.progress.proof
                ? {
                    ...item.progress.proof,
                    bytes_completed: item.progress.proof.bytes_total,
                    commitments_completed: item.progress.proof.commitments_total,
                  }
                : null,
            },
            retryable: false,
            attempt_history: item.attempt_history.map((attempt, index) =>
              index === 0
                ? { ...attempt, state: 'succeeded', completed_at_unix_ms: completedAt }
                : attempt,
            ),
          }
        : item,
    );
    setCaptureNotarization(operation.trace_id, 'succeeded');
    const capture = captures.find((item) => item.trace_id === operation.trace_id);
    if (capture) traces.set(capture.trace_id, traceForCapture(capture));
    recordEvent(
      'notarization_completed',
      'Sealing completed',
      'success',
      operation.trace_id,
      operationId,
    );
    progressingOperations.delete(operationId);
    operationPolls.delete(operationId);
  };
  const fixtureShare = (shareId: string, share: FixtureShareState): Share => ({
    trace_id: share.captureId,
    progress: share.progress,
    visibility: share.visibility,
    access_enabled: share.accessEnabled,
    password_protected: share.passwordProtected,
    expires_at_unix_ms: share.expiresAt,
    updated_at_unix_ms: share.updatedAt,
    failure_code: share.failureCode,
    share_url:
      share.progress === 'shared' && share.accessEnabled
        ? `https://notary.example/traces/${shareId}`
        : null,
    package_url:
      share.progress === 'shared' && share.accessEnabled
        ? `https://notary.example/api/public/traces/${shareId}/package.llmtrace`
        : null,
  });
  const status = (): Status => ({
    ...fixtureStatus,
    capture_mode: captureMode,
    counts: {
      captured: captures.filter((capture) => capture.state === 'captured').length,
      notarizing: captures.filter((capture) => capture.status === 'notarizing').length,
      notarized: captures.filter((capture) => capture.state === 'notarized').length,
      needs_attention: captures.filter((capture) =>
        ['capture_failed', 'notarization_failed', 'notarization_interrupted'].includes(
          capture.status ?? '',
        ),
      ).length,
      capturing: captures.filter((capture) => capture.status === 'capturing').length,
      capture_failed: captures.filter((capture) => capture.status === 'capture_failed').length,
    },
  });
  const filteredCaptures = (
    filters: Record<string, string | number | boolean | undefined> = {},
  ) => {
    const queryTerms = String(filters.query ?? '')
      .toLowerCase()
      .split(/[^\p{L}\p{N}_]+/u)
      .filter(Boolean);
    const state = String(filters.state ?? '');
    const status = String(filters.status ?? '');
    const provider = String(filters.provider ?? '');
    const model = String(filters.model ?? '');
    const streaming =
      filters.streaming === undefined
        ? null
        : filters.streaming === true || filters.streaming === 'true';
    const createdAfter = Number(filters.created_from_unix_ms ?? 0);
    return captures.filter(
      (capture) =>
        (queryTerms.length === 0 ||
          queryTerms.every((term) =>
            `${capture.prompt_preview} ${capture.output_preview} ${capture.requested_model}`
              .toLowerCase()
              .includes(term),
          )) &&
        (!state || capture.state === state) &&
        (!status ||
          capture.status === status ||
          (status === 'needs_attention' &&
            ['capture_failed', 'notarization_failed', 'notarization_interrupted'].includes(
              capture.status ?? '',
            ))) &&
        (!provider || capture.provider === provider) &&
        (!model || capture.requested_model === model) &&
        (streaming == null || capture.streaming === streaming) &&
        (!createdAfter || capture.created_at_unix_ms >= createdAfter),
    );
  };
  const cursorPosition = (value: unknown) => {
    if (typeof value !== 'string') return undefined;
    const position = Number(value.split(':').at(-1));
    return Number.isFinite(position) ? position : undefined;
  };
  const cursor = (kind: string, position: number) => `fixture:${kind}:${position}`;
  const traceDeletionSkipReason = (
    capture: TraceSummary,
  ): 'capture_active' | 'sealing_active' | 'share_active' | null => {
    if (capture.status === 'capturing') return 'capture_active';
    if (
      capture.status === 'notarizing' ||
      operations.some(
        (operation) =>
          operation.trace_id === capture.trace_id &&
          (operation.state === 'queued' || operation.state === 'running'),
      )
    ) {
      return 'sealing_active';
    }
    if (
      [...shares.values()].some(
        (share) =>
          share.captureId === capture.trace_id &&
          (share.progress === 'verifying' || share.accessEnabled),
      )
    ) {
      return 'share_active';
    }
    return null;
  };
  const removeTrace = (captureId: string) => {
    const operationIds = new Set(
      operations
        .filter((operation) => operation.trace_id === captureId)
        .map((operation) => operation.operation_id),
    );
    captures = captures.filter((capture) => capture.trace_id !== captureId);
    operations = operations.filter((operation) => operation.trace_id !== captureId);
    events = events.filter(
      (event) => event.trace_id !== captureId && !operationIds.has(event.operation_id ?? ''),
    );
    traces.delete(captureId);
    for (const [shareId, share] of shares) {
      if (share.captureId === captureId) shares.delete(shareId);
    }
  };
  return {
    session: async () => undefined,
    endSession: async () => undefined,
    status: async () => status(),
    captureSetting: async () => ({ mode: captureMode }),
    updateCaptureSetting: async (mode) => {
      if (captureMode !== mode) {
        captureMode = mode;
        const [eventType, message] = captureModeEvents[mode];
        recordEvent(eventType, message, 'info');
      }
      return { mode: captureMode };
    },
    autoSealSetting: async () => ({ enabled: autoSealEnabled }),
    updateAutoSealSetting: async (enabled) => {
      autoSealEnabled = enabled;
      return { enabled: autoSealEnabled };
    },
    notaries: async () => structuredClone(fixtureNotaries),
    providers: async () => ({
      providers: [
        [
          'openai',
          'OpenAI',
          'api.openai.com',
          'OpenAI Responses and Chat Completions',
          '/openai',
          '/openai/v1',
        ],
        [
          'openai_codex',
          'OpenAI Codex',
          'chatgpt.com',
          'OpenAI Responses (Codex)',
          '/codex',
          '/codex',
        ],
        [
          'anthropic',
          'Anthropic',
          'api.anthropic.com',
          'Anthropic Messages',
          '/anthropic',
          '/anthropic',
        ],
        [
          'deepseek',
          'DeepSeek',
          'api.deepseek.com',
          'OpenAI-compatible Chat Completions',
          '/deepseek',
          '/deepseek',
        ],
        [
          'openrouter',
          'OpenRouter',
          'openrouter.ai',
          'OpenAI-compatible Chat Completions',
          '/openrouter',
          '/openrouter/api/v1',
        ],
      ].map(([id, name, host, client_api, route_prefix, proxy_path]) => ({
        id,
        name,
        host,
        client_api,
        route_prefix,
        proxy_base_url: `http://127.0.0.1:8787${proxy_path}`,
        ready: true,
      })),
    }),
    traces: async (filters = {}) => {
      const limit = Number(filters.limit ?? 50);
      const all = filteredCaptures(filters);
      const start = cursorPosition(filters.cursor) ?? 0;
      const items = all.slice(start, start + limit);
      const next = start + items.length;
      return { items, next_cursor: next < all.length ? cursor('captures', next) : null };
    },
    trace: async (captureId) => {
      const operation = operations.find((item) => item.trace_id === captureId);
      if (operation && progressingOperations.has(operation.operation_id)) {
        advanceFixtureOperation(operation.operation_id);
      }
      const share = [...shares.entries()].find(([, value]) => value.captureId === captureId);
      return detail(
        captureId,
        captures,
        operations,
        share ? fixtureShare(share[0], share[1]) : null,
      );
    },
    deleteTrace: async (captureId) => {
      const capture = captures.find((item) => item.trace_id === captureId);
      if (!capture) return;
      const reason = traceDeletionSkipReason(capture);
      if (reason) {
        const code =
          reason === 'capture_active'
            ? 'trace_capture_active'
            : reason === 'sealing_active'
              ? 'trace_sealing_active'
              : 'trace_share_active';
        throw new LocalApiError(409, code, 'Trace cannot be deleted while work is active');
      }
      removeTrace(captureId);
    },
    startNotarization: async (captureId) => {
      const capture = captures.find((item) => item.trace_id === captureId);
      if (!capture) throw new LocalApiError(404, 'pending_capture_not_found', 'Trace not found');
      if (!capture.notarization_eligible) {
        throw new LocalApiError(
          409,
          capture.notarization_ineligibility_code ?? 'capture_not_eligible',
          'Trace is not eligible for sealing',
        );
      }
      const existing = operations.find((operation) => operation.trace_id === captureId);
      if (existing) {
        if (existing.retryable) {
          const queuedAt = actionTimestamp();
          operations = operations.map((operation) =>
            operation.operation_id === existing.operation_id
              ? {
                  ...operation,
                  state: 'queued',
                  failure_code: null,
                  completed_at_unix_ms: null,
                  progress: { phase: 'queued', updated_at_unix_ms: queuedAt, proof: null },
                  retryable: false,
                }
              : operation,
          );
          setCaptureNotarization(captureId, 'queued');
          operationPolls.delete(existing.operation_id);
          progressingOperations.add(existing.operation_id);
          recordEvent(
            'notarization_queued',
            'Sealing retry queued',
            'info',
            captureId,
            existing.operation_id,
          );
          const retried = operations.find(
            (operation) => operation.operation_id === existing.operation_id,
          );
          if (!retried) throw new Error('retried operation disappeared');
          return { trace_id: captureId, operation: retried, deduplicated: false };
        }
        return { trace_id: captureId, operation: existing, deduplicated: true };
      }
      const operation: Operation = {
        operation_id: 'op-notarize-queued-fixture',
        kind: 'notarization',
        trace_id: captureId,
        state: 'queued',
        attempt: 0,
        created_at_unix_ms: actionTimestamp(),
        progress: { phase: 'queued', updated_at_unix_ms: nextActionTime, proof: null },
        retryable: false,
        attempt_history: [],
      };
      operations = [operation, ...operations];
      setCaptureNotarization(captureId, 'queued');
      progressingOperations.add(operation.operation_id);
      recordEvent(
        'notarization_queued',
        'Sealing queued',
        'info',
        captureId,
        operation.operation_id,
      );
      return { trace_id: captureId, operation, deduplicated: false };
    },
    events: async (filters = {}) => {
      const pagePosition = cursorPosition(filters.cursor);
      const after = cursorPosition(filters.after);
      const createdAfter = Number(filters.created_after_unix_ms ?? 0);
      const limit = Number(filters.limit ?? 100);
      const matching = events.filter(
        (event) =>
          (after === undefined
            ? pagePosition === undefined || event.event_id < pagePosition
            : event.event_id > (pagePosition ?? after)) &&
          (!filters.severity || event.severity === filters.severity) &&
          (!filters.event_type || event.event_type === filters.event_type) &&
          (!filters.trace_id || event.trace_id === filters.trace_id) &&
          (!filters.operation_id || event.operation_id === filters.operation_id) &&
          (!createdAfter || event.created_at_unix_ms >= createdAfter),
      );
      if (after !== undefined) matching.sort((left, right) => left.event_id - right.event_id);
      const items = matching.slice(0, limit);
      const lastItem = items.at(-1);
      return {
        items,
        next_cursor:
          matching.length > limit && lastItem ? cursor('events', lastItem.event_id) : null,
        high_water_cursor: events.length ? cursor('events', events[0].event_id) : null,
      };
    },
    traceContent: async (captureId) => {
      const trace = traces.get(captureId);
      if (!trace)
        throw new LocalApiError(404, 'notarized_trace_not_found', 'Sealed trace not found');
      return structuredClone(trace);
    },
    downloadPackage: async (captureId) =>
      new Blob([`fixture .llmtrace for ${captureId}`], {
        type: 'application/vnd.exalto.notary.trace-package+zip',
      }),
    verify: async (captureId) => {
      if (!traces.has(captureId))
        throw new LocalApiError(422, 'trace_verification_failed', 'Trace verification failed');
      return {
        ...fixtureVerification,
        trace_id: captureId,
        verified_at_unix_ms: fixtureVerification.verified_at_unix_ms + offset,
      };
    },
    account: async () => account,
    startAccountConnection: async () => ({
      request_id: 'auth-docs-fixture',
      user_code: '7A3C-91F2',
      verification_uri_complete: 'https://notary.example/authorize?user_code=7A3C-91F2',
      expires_in_seconds: 600,
      poll_interval_seconds: 0,
      state: 'pending',
    }),
    pollAccountConnection: async () => {
      account = {
        ...account,
        signed_in: true,
        connection_state: 'connected',
        provider_display_name: 'sample-user',
        display_name: 'Sample User',
        device_name: 'Admin dashboard',
        credential_kind: 'device_session',
        credential_name: 'Admin dashboard',
      };
      return account;
    },
    disconnectAccount: async () => {
      account = { signed_in: false, connection_state: 'disconnected', links: account.links };
    },
    share: async (captureId, settings) => {
      if (!traces.has(captureId))
        throw new LocalApiError(404, 'notarized_trace_not_found', 'Sealed trace not found');
      const existing = [...shares.entries()].find(([, share]) => share.captureId === captureId);
      const shareId = existing?.[0] ?? 'share-fixture';
      const previous = existing?.[1];
      const updatedAt = actionTimestamp();
      const share: FixtureShareState = {
        captureId,
        progress:
          previous?.progress === 'stopped'
            ? settings.reactivate
              ? 'shared'
              : 'stopped'
            : previous?.progress === 'shared'
              ? 'shared'
              : 'verifying',
        visibility: settings.visibility,
        accessEnabled:
          previous?.progress === 'stopped'
            ? Boolean(settings.reactivate)
            : previous?.progress === 'shared' && previous.accessEnabled === false
              ? settings.expires_in_days != null
              : true,
        passwordProtected:
          settings.password == null
            ? (previous?.passwordProtected ?? false)
            : settings.password.length > 0,
        expiresAt:
          settings.expires_in_days == null
            ? (previous?.expiresAt ?? null)
            : settings.expires_in_days === 0
              ? null
              : updatedAt + settings.expires_in_days * 24 * hour,
        failureCode: null,
        updatedAt,
      };
      shares.set(shareId, share);
      return fixtureShare(shareId, share);
    },
    shareStatus: async (captureId) => {
      const entry = [...shares.entries()].find(([, share]) => share.captureId === captureId);
      if (!entry) throw new LocalApiError(404, 'share_not_found', 'Share not found');
      const [shareId, share] = entry;
      const result = fixtureShare(shareId, share);
      if (share.progress === 'verifying') share.progress = 'shared';
      share.updatedAt = actionTimestamp();
      return result;
    },
    stopSharing: async (captureId) => {
      const entry = [...shares.entries()].find(([, share]) => share.captureId === captureId);
      if (!entry) throw new LocalApiError(404, 'share_not_found', 'Share not found');
      const [shareId, share] = entry;
      share.accessEnabled = false;
      share.progress = 'stopped';
      share.updatedAt = actionTimestamp();
      return fixtureShare(shareId, share);
    },
  };
}
