export type NotaryStatus = 'active' | 'retiring' | 'retired' | 'revoked' | 'configured';

export type NotaryLifecycleRecord = {
  key_id: string;
  lifecycle: NotaryStatus | string;
  valid_from_unix_ms?: number | null;
};

const lifecycleOrder: Record<NotaryStatus, number> = {
  active: 0,
  retiring: 1,
  retired: 2,
  revoked: 3,
  configured: 4,
};

export function notaryLifecycle(status: string) {
  switch (status) {
    case 'active':
      return {
        label: 'Accepts new captures and sealing',
        description:
          'May accept new captures and sealing requests only while its configured windows permit.',
      };
    case 'retiring':
      return {
        label: 'Sealing-only',
        description:
          'May seal compatible existing capture checkpoints until its configured cutoff. It does not accept new captures.',
      };
    case 'retired':
      return {
        label: 'Historical verification only',
        description:
          'Retained only to verify evidence from its configured trust window. It cannot accept captures or sealing requests.',
      };
    case 'revoked':
      return {
        label: 'Untrusted',
        description: 'Revoked and not trusted for capture, sealing, or historical verification.',
      };
    case 'configured':
      return {
        label: 'Explicit self-hosted configuration',
        description:
          'Used because this endpoint and key are configured together locally. It has no hosted Registry lifecycle or health status.',
      };
    default:
      return {
        label: 'Unknown lifecycle',
        description:
          'This client does not recognize the reported lifecycle state and does not present the record as usable.',
      };
  }
}

export function orderNotaries<T extends NotaryLifecycleRecord>(
  records: T[],
  activeKeyId?: string | null,
): T[] {
  return [...records].sort((left, right) => {
    const leftSelected = left.key_id === activeKeyId ? -1 : 0;
    const rightSelected = right.key_id === activeKeyId ? -1 : 0;
    if (leftSelected !== rightSelected) return leftSelected - rightSelected;
    const leftOrder = lifecycleOrder[left.lifecycle as NotaryStatus] ?? 99;
    const rightOrder = lifecycleOrder[right.lifecycle as NotaryStatus] ?? 99;
    if (leftOrder !== rightOrder) return leftOrder - rightOrder;
    const validFrom = (right.valid_from_unix_ms ?? 0) - (left.valid_from_unix_ms ?? 0);
    return validFrom || left.key_id.localeCompare(right.key_id);
  });
}

export function abbreviatedKeyId(keyId: string) {
  return keyId.length > 28 ? `${keyId.slice(0, 18)}…${keyId.slice(-8)}` : keyId;
}

export function formatNotaryBoundary(
  value: number | null | undefined,
  {
    kind = 'cutoff',
    missingLabel,
    locales,
    timeZone,
  }: {
    kind?: 'lower' | 'cutoff';
    missingLabel?: string;
    locales?: Intl.LocalesArgument;
    timeZone?: string;
  } = {},
) {
  if (kind === 'lower' && value === 0) return 'No lower bound configured';
  if (value === undefined || value === null) {
    return (
      missingLabel ?? (kind === 'lower' ? 'No lower bound configured' : 'No cutoff configured')
    );
  }
  return new Intl.DateTimeFormat(locales, {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone,
  }).format(new Date(value));
}
