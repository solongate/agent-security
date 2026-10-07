// SPDX-License-Identifier: Apache-2.0

/** Data-loading hooks shared by the TUI panels. */
import { useCallback, useEffect, useRef, useState } from 'react';

export interface LoaderState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
  /** Refetch WITHOUT flipping `loading` — for background polls, so the
   *  visible "loading…" is reserved for user actions (filters, paging). */
  reloadQuiet: () => void;
}

/**
 * Load async data once (and on demand via reload()). Safe against unmount —
 * a resolve after the component is gone is ignored.
 */
export function useLoader<T>(fn: () => Promise<T>, deps: unknown[] = []): LoaderState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const alive = useRef(true);
  const quiet = useRef(false);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  useEffect(() => {
    if (!quiet.current) setLoading(true);
    quiet.current = false;
    fnRef
      .current()
      .then((d) => {
        if (!alive.current) return;
        setData(d);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!alive.current) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (alive.current) setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const reloadQuiet = useCallback(() => {
    quiet.current = true;
    setNonce((n) => n + 1);
  }, []);
  return { data, error, loading, reload, reloadQuiet };
}

/** Fire `reload` on a fixed interval (ms). Cleans up on unmount. */
export function usePoll(reload: () => void, intervalMs: number, enabled = true): void {
  useEffect(() => {
    if (!enabled) return;
    const t = setInterval(reload, intervalMs);
    return () => clearInterval(t);
  }, [reload, intervalMs, enabled]);
}

/** Live terminal size — re-renders on resize so every layout stays responsive. */
export function useTermSize(): { cols: number; rows: number } {
  const read = () => ({ cols: process.stdout.columns ?? 100, rows: process.stdout.rows ?? 30 });
  const [size, setSize] = useState(read);
  useEffect(() => {
    const onResize = () => setSize(read());
    process.stdout.on('resize', onResize);
    return () => {
      process.stdout.off('resize', onResize);
    };
  }, []);
  return size;
}

/**
 * Content area available to a boxed panel inside the App shell (banner + nav +
 * borders + key hints subtracted). Panels size their lists from this so nothing
 * overflows the box at any terminal size.
 */
export function usePanelSize(): { cols: number; rows: number } {
  const { cols, rows } = useTermSize();
  const wide = cols >= 82; // full ASCII banner (6 lines + subtitle) vs 1-line title
  // Reserve: paddingTop(1) + banner(7 wide / 1 narrow) + account bar(1) +
  // marginTop(1) + box borders(2) + key hints(1) + 2 lines headroom so the
  // total never reaches stdout.rows (which would clearTerminal-repaint and
  // slide the banner). Narrow keeps the same non-banner overhead.
  const shellRows = wide ? 16 : 10;
  return { cols: Math.max(30, cols - 22), rows: Math.max(8, rows - shellRows) };
}
