import { invoke } from '@tauri-apps/api/core';
import { type ComponentType, useEffect, useState } from 'react';
import { isTauri } from './bridge';

type SymbolWeight = 'regular' | 'medium' | 'semibold';

const cache = new Map<string, Promise<string | null>>();

/** Ask AppKit for an SF Symbol as a mask image. Resolves null when unavailable. */
function loadSymbol(name: string, pointSize: number, weight: SymbolWeight) {
  const key = `${name}:${pointSize}:${weight}`;
  let pending = cache.get(key);
  if (!pending) {
    pending = isTauri()
      ? invoke<string | null>('system_symbol', {
          name,
          pointSize,
          weight,
          scale: Math.max(2, window.devicePixelRatio || 2),
        }).catch(() => null)
      : Promise.resolve(null);
    cache.set(key, pending);
  }
  return pending;
}

type FallbackIcon = ComponentType<{
  size?: number;
  strokeWidth?: number;
  'aria-hidden'?: boolean | 'true';
}>;

/**
 * An SF Symbol rendered by the system and tinted with the current text colour.
 * Outside the Mac app, or for a symbol this macOS does not have, the Lucide
 * fallback draws instead so the shell keeps working in the browser tests.
 */
export function SfSymbol({
  name,
  fallback: Fallback,
  size = 16,
  weight = 'medium',
  className,
}: {
  name: string;
  fallback: FallbackIcon;
  size?: number;
  weight?: SymbolWeight;
  className?: string;
}) {
  const [image, setImage] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    void loadSymbol(name, size, weight).then((url) => {
      if (alive) setImage(url);
    });
    return () => {
      alive = false;
    };
  }, [name, size, weight]);
  if (!image) return <Fallback size={size} strokeWidth={1.8} aria-hidden="true" />;
  return (
    <span
      className={`sf-symbol${className ? ` ${className}` : ''}`}
      aria-hidden="true"
      style={{
        width: size,
        height: size,
        WebkitMaskImage: `url(${image})`,
        maskImage: `url(${image})`,
      }}
    />
  );
}
