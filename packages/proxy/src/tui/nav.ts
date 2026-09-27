/**
 * Cross-panel navigation: lets a panel ask the shell to OPEN another section
 * (e.g. Policies pressing D jumps straight into Dry Run instead of telling the
 * user to go there). The App subscribes once and applies the request.
 */
let pending: string | null = null;
const subs = new Set<() => void>();

/** Ask the shell to switch to (and focus) the section with this label. */
export function requestSection(label: string): void {
  pending = label;
  for (const fn of subs) fn();
}

/** Consume the pending request (returns null when there is none). */
export function takePendingSection(): string | null {
  const p = pending;
  pending = null;
  return p;
}

/** Subscribe to requests. Returns an unsubscribe function. */
export function onSectionRequest(fn: () => void): () => void {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
}
