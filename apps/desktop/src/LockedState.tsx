import { ChevronRight, KeyRound } from 'lucide-react';
import { useState } from 'react';
import { errorMessage, startDaemon, unlockVault } from './bridge';
import notaryMark from './notary-mark.svg';

export function LoadingWindow() {
  return (
    <div className="loading-window">
      <img src={notaryMark} alt="" />
      <span>Opening Exalto Capture…</span>
    </div>
  );
}

export function VaultUnlock({ refresh }: { refresh: () => Promise<void> }) {
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const unlock = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await unlockVault(passphrase);
      setPassphrase('');
      await startDaemon();
      await new Promise((resolve) => window.setTimeout(resolve, 700));
      await refresh();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="onboarding-window unlock-window">
      <header className="onboarding-toolbar" data-tauri-drag-region="deep">
        <div className="traffic-light-space" data-tauri-drag-region />
        <strong className="onboarding-window-title" data-tauri-drag-region>
          Exalto Capture
        </strong>
        <span className="onboarding-window-context">Locked</span>
      </header>
      <main className="unlock-body">
        <form className="unlock-card" onSubmit={(event) => void unlock(event)}>
          <span className="unlock-icon">
            <KeyRound />
          </span>
          <span className="wizard-kicker">Private trace vault</span>
          <h1>Unlock private traces on this Mac</h1>
          <p>
            Enter the passphrase you chose during setup. Exalto Capture keeps it only for this app
            session.
          </p>
          <label>
            <span>Vault passphrase</span>
            <input
              type="password"
              autoComplete="current-password"
              // biome-ignore lint/a11y/noAutofocus: the lock screen's only task is entering the passphrase, so focus starts in its sole field.
              autoFocus
              value={passphrase}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? 'vault-unlock-error' : undefined}
              onChange={(event) => setPassphrase(event.target.value)}
            />
          </label>
          {error && (
            <div id="vault-unlock-error" className="onboarding-error" role="alert">
              {error}
            </div>
          )}
          <button className="mac-button is-primary is-large" type="submit" disabled={busy}>
            {busy ? 'Unlocking…' : 'Unlock Exalto Capture'} <ChevronRight size={15} />
          </button>
        </form>
      </main>
    </div>
  );
}
