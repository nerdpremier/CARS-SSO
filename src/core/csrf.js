let csrfToken = null;

export async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  const res = await fetch("/api/csrf", { credentials: "include" });
  if (!res.ok) throw new Error("ไม่สามารถขอ CSRF token ได้");
  const data = await res.json();
  if (!data || typeof data.token !== "string" || !data.token) {
    throw new Error("CSRF token ไม่ถูกต้อง");
  }
  csrfToken = data.token;
  return csrfToken;
}

async function secureHeaders() {
  const token = await getCsrfToken();
  return { "Content-Type": "application/json", "X-CSRF-Token": token };
}

export async function secureFetch(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = await secureHeaders();
    const res = await fetch(url, {
      ...options,
      credentials: "include",
      headers: { ...headers, ...(options.headers || {}) },
      signal: controller.signal,
    });
    if (res.status === 403) {
      csrfToken = null;
      const retryController = new AbortController();
      const retryTimeoutId = setTimeout(() => retryController.abort(), timeoutMs);
      try {
        const retryHeaders = await secureHeaders();
        return await fetch(url, {
          ...options,
          credentials: "include",
          headers: { ...retryHeaders, ...(options.headers || {}) },
          signal: retryController.signal,
        });
      } finally {
        clearTimeout(retryTimeoutId);
      }
    }
    return res;
  } finally {
    clearTimeout(timeoutId);
  }
}
