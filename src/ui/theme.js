const KEY = "cars_theme";

export function setTheme(explicit) {
  const root = document.body;
  const stored = explicit || safeGet(KEY) || "dark";
  const theme = stored === "light" ? "light" : "dark";
  root.setAttribute("data-theme", theme);
  safeSet(KEY, theme);
  return theme;
}

export function toggleTheme() {
  const current = document.body.getAttribute("data-theme") || "dark";
  return setTheme(current === "dark" ? "light" : "dark");
}

function safeGet(k) {
  try {
    return localStorage.getItem(k);
  } catch {
    return null;
  }
}
function safeSet(k, v) {
  try {
    localStorage.setItem(k, v);
  } catch {}
}
