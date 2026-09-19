"use client";

import { useEffect, useState } from "react";

function storage(): Storage | null {
  if (typeof window === "undefined") {
    return null;
  }
  return window.localStorage;
}

export function readCached<T>(key: string): T | null {
  const store = storage();
  if (!store) {
    return null;
  }
  try {
    const raw = store.getItem(key);
    if (!raw) {
      return null;
    }
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function writeCached<T>(key: string, value: T): void {
  const store = storage();
  if (!store) {
    return;
  }
  try {
    store.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore storage failures and keep runtime state only.
  }
}

/**
 * Hydration-safe cached state.
 *
 * SSR renders `initial`; after mount the cached value (if any) replaces it in
 * a separate render pass, so the server HTML and the first client render are
 * identical. Use this instead of `useState(() => readCached(...))`, whose
 * localStorage read makes the first client render differ from SSR (React #418).
 */
export function useCachedState<T>(key: string, initial: T): [T, React.Dispatch<React.SetStateAction<T>>] {
  const [value, setValue] = useState<T>(initial);
  useEffect(() => {
    const cached = readCached<T>(key);
    if (cached !== null) {
      setValue(cached);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  return [value, setValue];
}
