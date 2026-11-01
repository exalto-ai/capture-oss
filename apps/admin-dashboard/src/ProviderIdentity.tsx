import type { CSSProperties, ReactNode } from 'react';
import './provider-identity.css';

const providerIcons = {
  anthropic: new URL('./assets/providers/anthropic.svg', import.meta.url).href,
  deepseek: new URL('./assets/providers/deepseek.svg', import.meta.url).href,
  openai: new URL('./assets/providers/openai.svg', import.meta.url).href,
  openrouter: new URL('./assets/providers/openrouter.svg', import.meta.url).href,
} as const;

export type ProviderIconKey = keyof typeof providerIcons | 'unknown';

export function providerIconKey(provider?: string | null): ProviderIconKey {
  const normalized = provider?.trim().toLowerCase();
  return normalized && Object.hasOwn(providerIcons, normalized)
    ? (normalized as keyof typeof providerIcons)
    : 'unknown';
}

export function ProviderIdentity({
  provider,
  fallback = 'Provider not reported',
  detail,
  className = '',
}: {
  provider?: string | null;
  fallback?: string;
  detail?: ReactNode;
  className?: string;
}) {
  const key = providerIconKey(provider);
  const label = provider?.trim() || fallback;
  const iconUrl = key === 'unknown' ? null : providerIcons[key];
  const iconStyle = iconUrl
    ? ({ '--provider-icon-url': `url("${iconUrl}")` } as CSSProperties)
    : undefined;

  return (
    <span className={`provider-identity ${className}`.trim()} data-provider-icon={key}>
      {iconUrl ? (
        <span className="provider-identity__icon" style={iconStyle} aria-hidden="true" />
      ) : (
        <svg
          className="provider-identity__icon provider-identity__icon--unknown"
          viewBox="0 0 24 24"
          fill="none"
          aria-hidden="true"
        >
          <path d="M4.5 7.5 12 3l7.5 4.5v9L12 21l-7.5-4.5v-9Z" />
          <circle cx="12" cy="12" r="2.5" />
        </svg>
      )}
      <span className="provider-identity__name">{label}</span>
      {detail !== undefined && detail !== null && (
        <span className="provider-identity__detail">{detail}</span>
      )}
    </span>
  );
}
