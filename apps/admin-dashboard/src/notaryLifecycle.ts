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
          'Used because this endpoint and key are configured together in the server configuration. It has no hosted Registry lifecycle or health status.',
      };
    default:
      return {
        label: 'Unknown lifecycle',
        description:
          'This client does not recognize the reported lifecycle state and does not present the record as usable.',
      };
  }
}

export function abbreviatedKeyId(keyId: string) {
  return keyId.length > 28 ? `${keyId.slice(0, 18)}…${keyId.slice(-8)}` : keyId;
}

export function formatNotaryBoundary(
  value: number | null | undefined,
  {
    kind = 'cutoff',
    missingLabel,
  }: {
    kind?: 'lower' | 'cutoff';
    missingLabel?: string;
  } = {},
) {
  if (kind === 'lower' && value === 0) return 'No lower bound configured';
  if (value === undefined || value === null) {
    return (
      missingLabel ?? (kind === 'lower' ? 'No lower bound configured' : 'No cutoff configured')
    );
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}
