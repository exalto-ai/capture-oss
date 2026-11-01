import { ArrowUp, Square } from 'lucide-react';
import type { ReactNode, Ref } from 'react';
import { SfSymbol } from './SfSymbol';

/** The composer card: the message field on top, its controls and Send below. */
export function ChatComposer({
  value,
  onChange,
  onSend,
  onStop,
  busy,
  canSend,
  disabled,
  placeholder,
  inputRef,
  controls,
}: {
  value: string;
  onChange: (value: string) => void;
  onSend: () => void;
  onStop: () => void;
  busy: boolean;
  canSend: boolean;
  disabled: boolean;
  placeholder: string;
  inputRef: Ref<HTMLTextAreaElement>;
  controls: ReactNode;
}) {
  return (
    <form
      className="chat-composer"
      onSubmit={(e) => {
        e.preventDefault();
        onSend();
      }}
    >
      <textarea
        ref={inputRef}
        aria-label="Message"
        placeholder={placeholder}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
            e.preventDefault();
            onSend();
          }
        }}
        rows={1}
      />
      <div className="chat-composer-bar">
        {controls}
        {busy ? (
          <button
            className="chat-send is-stop"
            type="button"
            aria-label="Stop"
            title="Stop"
            onClick={onStop}
          >
            <SfSymbol name="stop.fill" fallback={Square} size={10} />
          </button>
        ) : (
          <button
            className="chat-send"
            type="submit"
            aria-label="Send"
            title="Send"
            disabled={!canSend}
          >
            <SfSymbol name="arrow.up" fallback={ArrowUp} size={13} weight="semibold" />
          </button>
        )}
      </div>
    </form>
  );
}
