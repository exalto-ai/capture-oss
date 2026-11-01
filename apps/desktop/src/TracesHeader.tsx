import { Button, SegmentedControl, Switch } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type CaptureMode, captures, type DesktopState, errorMessage, localApi } from './bridge';
import type { View } from './product';

const captureModeOptions: { value: CaptureMode; label: string }[] = [
  { value: 'off', label: 'Off' },
  { value: 'witnessed', label: 'Witnessed' },
  { value: 'notarized', label: 'Notarized' },
];

/**
 * The main screen's header: Traces, with the auto-seal switch and the capture
 * mode chooser beside it. Capture is only possible once the sealing service's
 * trusted transport is reachable, so the header also says when it is not.
 */
export function TracesHeader({
  state,
  busy,
  notice,
  onChooseCaptureMode,
  onRetryConnections,
  onNavigate,
}: {
  state: DesktopState;
  busy: string | null;
  notice: string | null;
  onChooseCaptureMode: (mode: CaptureMode) => void;
  onRetryConnections: () => void;
  onNavigate: (view: View) => void;
}) {
  const mode: CaptureMode = state.running ? state.capture_mode : 'off';
  const recording = captures(mode);
  const queryClient = useQueryClient();
  const autoSeal = useQuery({
    queryKey: ['auto-seal'],
    queryFn: localApi.autoSealSetting,
    enabled: state.running,
  });
  const setAutoSeal = useMutation({
    mutationFn: localApi.updateAutoSealSetting,
    onSuccess: (setting) => queryClient.setQueryData(['auto-seal'], setting),
    onError: (error) =>
      notifications.show({ color: 'red', title: 'Auto-seal', message: errorMessage(error) }),
  });
  const autoSealing = autoSeal.data?.enabled === true;
  const sealingServiceName = state.sealing_service?.name ?? 'Exalto Seal';
  const sealingPhase = state.sealing_service_readiness.phase;
  const sealingReady = sealingPhase === 'ready';
  const captureCanStart = sealingReady || (!state.running && sealingPhase === 'off');
  const sealingStarting = sealingPhase === 'starting';
  const sealingNeedsAttention =
    sealingPhase === 'unreachable' || sealingPhase === 'trust_unavailable';
  const status =
    busy === 'capture-start'
      ? 'Starting capture…'
      : recording
        ? mode === 'witnessed'
          ? 'Capturing, Witnessed. Each trace is sealed as soon as it completes.'
          : autoSealing
            ? 'Capturing. New traces are sealed as they arrive.'
            : 'Capturing. Make a request in a connected AI client.'
        : sealingStarting
          ? `Checking the connection to ${sealingServiceName}. Capture is available when it succeeds.`
          : 'Capture is off. Requests sent while it is off can’t be sealed later.';
  const message = notice ?? (state.running ? state.message : null);

  return (
    <header className="native-page-header traces-header" data-tauri-drag-region="deep">
      <div>
        <h1 data-tauri-drag-region>Traces</h1>
        <p className={recording ? 'is-recording' : undefined}>{status}</p>
      </div>
      <div className="traces-header-switches">
        <Switch
          className="capture-switch"
          label="Auto-seal"
          labelPosition="left"
          size="md"
          checked={autoSealing}
          disabled={!autoSeal.isSuccess || setAutoSeal.isPending}
          title="Seal each new trace as it is captured. Each seal uses your monthly sealing allowance."
          onChange={(event) => setAutoSeal.mutate(event.currentTarget.checked)}
        />
        <div
          className="capture-mode"
          title={
            recording || captureCanStart
              ? undefined
              : `Capture needs a reachable connection to ${sealingServiceName}.`
          }
        >
          <span aria-hidden="true">Capture</span>
          <SegmentedControl
            aria-label="Capture mode"
            size="xs"
            value={mode}
            disabled={busy !== null}
            data={captureModeOptions.map((option) => ({
              ...option,
              disabled: option.value !== 'off' && !recording && !captureCanStart,
            }))}
            onChange={(value) => {
              if (value !== mode) onChooseCaptureMode(value as CaptureMode);
            }}
          />
        </div>
      </div>
      <p className="capture-mode-note">
        Witnessed sends your prompts and API key to the notary, which relays the exchange and
        vouches for it. Notarized keeps both from the notary and produces a TLSNotary proof when a
        trace is sealed.
      </p>
      {sealingNeedsAttention && (
        <div className="traces-header-alert" role="status">
          <div>
            <strong>
              {sealingPhase === 'unreachable'
                ? `${sealingServiceName} can’t be reached`
                : 'Sealing trust needs attention'}
            </strong>
            <span>
              {state.sealing_service_readiness.message ??
                (sealingPhase === 'unreachable'
                  ? 'The trusted endpoint did not complete its transport handshake.'
                  : 'The configured trust source did not resolve a trusted sealing endpoint.')}
            </span>
          </div>
          <Button size="xs" variant="outline" onClick={onRetryConnections}>
            Try again
          </Button>
          <Button size="xs" variant="subtle" onClick={() => onNavigate('settings')}>
            Sealing settings
          </Button>
        </div>
      )}
      {message && (
        <p className="traces-header-notice" role="status">
          {message}
        </p>
      )}
    </header>
  );
}
