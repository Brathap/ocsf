/**
 * Centralized API Client & Security Configuration for ULPF Frontend.
 * Ensures consistent authentication headers and air-gapped API routing.
 */

// Configurable API key support with operator/admin fallback
export const getApiKey = (): string => {
  if (typeof window !== "undefined") {
    const stored = localStorage.getItem("ulpf_auth_token");
    if (stored) return stored;
  }
  return (import.meta as any).env?.VITE_ULPF_API_KEY || "ulpf_admin_secret_key_2026";
};

export const setApiKey = (key: string): void => {
  if (typeof window !== "undefined") {
    localStorage.setItem("ulpf_auth_token", key);
  }
};

// Dynamic base URL respecting deployment origin
export const getApiBaseUrl = (): string => {
  if ((import.meta as any).env?.VITE_API_BASE_URL) {
    return (import.meta as any).env.VITE_API_BASE_URL;
  }
  if (typeof window !== "undefined") {
    // If running in development with Vite proxy (e.g. port 5173, 5174, etc.)
    // returning empty string allows relative URLs like /api/... to be transparently proxied
    return "";
  }
  return "http://localhost:8000";
};

export const ULPF_API_KEY = getApiKey();
export const API_BASE_URL = getApiBaseUrl();

/**
 * Returns default headers including X-API-Key for authenticated requests.
 */
export function getAuthHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
  return {
    "X-API-Key": getApiKey(),
    ...extraHeaders,
  };
}

/**
 * Authenticated fetch wrapper.
 */
export async function secureFetch(endpoint: string, options: RequestInit = {}): Promise<Response> {
  const baseUrl = getApiBaseUrl();
  const url = endpoint.startsWith("http") ? endpoint : `${baseUrl}${endpoint}`;
  const headers = getAuthHeaders(options.headers as Record<string, string> || {});
  return fetch(url, {
    ...options,
    headers,
  });
}

/**
 * Formats SSE or direct download URLs with authenticated query parameters.
 */
export function getAuthenticatedUrl(path: string): string {
  const baseUrl = getApiBaseUrl();
  const key = getApiKey();
  const base = path.startsWith("http") ? path : `${baseUrl}${path}`;
  const separator = base.includes("?") ? "&" : "?";
  return `${base}${separator}api_key=${encodeURIComponent(key)}`;
}
