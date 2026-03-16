import { secureFetch } from "./csrf.js";

export async function getSession() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    let res;
    try {
      res = await fetch("/api/session", { credentials: "include", signal: controller.signal });
    } finally {
      clearTimeout(timeoutId);
    }
    if (!res.ok) return { authenticated: false };
    const data = await res.json();
    if (!data || !data.authenticated) return { authenticated: false };
    return { authenticated: true, user: typeof data.user === "string" ? data.user : "" };
  } catch {
    return { authenticated: false };
  }
}

export async function logout() {
  try {
    await secureFetch("/api/logout", { method: "POST" });
  } catch {}
}

