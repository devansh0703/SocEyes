"use client";

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
