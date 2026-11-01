import { FileCheck2, MessageSquare, Settings } from 'lucide-react';
import type { DesktopState } from './bridge';
import notaryMark from './notary-mark.svg';
import { DISPLAY_NAME, type View } from './product';
import { SfSymbol } from './SfSymbol';

export function Sidebar({
  state,
  view,
  onNavigate,
}: {
  state: DesktopState;
  view: View;
  onNavigate: (view: View) => void;
}) {
  const traceCount =
    state.counts.captured +
    state.counts.notarized +
    state.counts.capturing +
    state.counts.capture_failed;
  const items: Array<{
    view: View;
    label: string;
    icon: typeof FileCheck2;
    symbol: string;
    count?: number;
  }> = [
    {
      view: 'traces',
      label: 'Traces',
      icon: FileCheck2,
      symbol: 'doc.text',
      count: traceCount,
    },
    { view: 'chat', label: 'Chat', icon: MessageSquare, symbol: 'bubble.left' },
    { view: 'settings', label: 'Settings', icon: Settings, symbol: 'gearshape' },
  ];

  return (
    <aside className="native-sidebar">
      <div className="sidebar-drag-region" data-tauri-drag-region />
      <div className="sidebar-brand">
        <img src={notaryMark} alt="" />
        <strong>Capture</strong>
      </div>
      <nav aria-label={DISPLAY_NAME}>
        <div className="sidebar-group">
          {items.map(({ view: itemView, label, icon: Icon, symbol, count }) => (
            <button
              key={itemView}
              type="button"
              className={view === itemView ? 'is-selected' : ''}
              onClick={() => onNavigate(itemView)}
            >
              <SfSymbol name={symbol} fallback={Icon} size={16} />
              <span>{label}</span>
              {count ? <b>{count}</b> : null}
            </button>
          ))}
        </div>
      </nav>
    </aside>
  );
}
