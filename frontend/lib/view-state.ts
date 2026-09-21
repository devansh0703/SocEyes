"use client";

import { useEffect, useState } from "react";

export type GlobalViewState = {
  preset: string;
  start: string;
  end: string;
  selectedRunId: string;
};

const STORAGE_KEY = "soceyes-global-view-state";
const EVENT_NAME = "soceyes:view-state";

const DEFAULT_STATE: GlobalViewState = {
  preset: "now-5h",
  start: "",
  end: "",
  selectedRunId: "",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function sanitizeState(value: unknown): GlobalViewState {
  if (!isRecord(value)) {
    return DEFAULT_STATE;
  }
  return {
    preset: typeof value.preset === "string" && value.preset ? value.preset : DEFAULT_STATE.preset,
    start: typeof value.start === "string" ? value.start : "",
    end: typeof value.end === "string" ? value.end : "",
    selectedRunId: typeof value.selectedRunId === "string" ? value.selectedRunId : "",
  };
}

export function readGlobalViewState(): GlobalViewState {
  if (typeof window === "undefined") {
    return DEFAULT_STATE;
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return DEFAULT_STATE;
    }
    return sanitizeState(JSON.parse(raw));
  } catch {
    return DEFAULT_STATE;
  }
}

export function writeGlobalViewState(nextState: GlobalViewState): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(nextState));
  window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: nextState }));
}

export function resolveTimeWindow(viewState: GlobalViewState): { start?: string; end?: string } {
  if (viewState.start || viewState.end) {
    return {
      start: viewState.start || undefined,
      end: viewState.end || undefined,
    };
  }
  return { start: viewState.preset || DEFAULT_STATE.preset };
}

export function useGlobalViewState(): [GlobalViewState, (nextState: GlobalViewState) => void] {
  const [state, setState] = useState<GlobalViewState>(DEFAULT_STATE);

  useEffect(() => {
    setState(readGlobalViewState());

    const storageListener = (event: StorageEvent) => {
      if (event.key === STORAGE_KEY) {
        setState(readGlobalViewState());
      }
    };

    const customListener = () => {
      setState(readGlobalViewState());
    };

    window.addEventListener("storage", storageListener);
    window.addEventListener(EVENT_NAME, customListener as EventListener);

    return () => {
      window.removeEventListener("storage", storageListener);
      window.removeEventListener(EVENT_NAME, customListener as EventListener);
    };
  }, []);

  const update = (nextState: GlobalViewState) => {
    setState(nextState);
    writeGlobalViewState(nextState);
  };

  return [state, update];
}
