// Dispose resources on cancellation, including cancellation during acquisition.
export function onAbort(signal: AbortSignal | undefined, dispose: () => Promise<unknown> | void): () => void {
  const abort = () => { void Promise.resolve(dispose()).catch(() => {}); };
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();
  return () => signal?.removeEventListener("abort", abort);
}

export function acquire<T>(pending: Promise<T>, signal: AbortSignal | undefined, dispose: (resource: T) => Promise<unknown>): Promise<T> {
  if (!signal) return pending;
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    pending.then(resource => {
      signal.removeEventListener("abort", abort);
      if (signal.aborted) { void dispose(resource).catch(() => {}); reject(signal.reason); }
      else resolve(resource);
    }, error => { signal.removeEventListener("abort", abort); reject(error); });
  });
}
