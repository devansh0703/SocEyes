"use client";

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "";

export function buildQuery(params: Record<string, string | number | undefined | null>) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") {
      return;
    }
    query.set(key, String(value));
  });
  return query.toString();
}

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const baseUrl = API_URL || "";
  const url = `${baseUrl}${path}`;
  
  try {
    const response = await fetch(url, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers || {})
      },
      cache: "no-store",
    });
    
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `Request failed with ${response.status}`);
    }
    
    const data = await response.json();
    return data as T;
  } catch (error) {
    console.error(`API fetch failed for ${path}:`, error);
    throw error;
  }
}
