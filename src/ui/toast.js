const stackId = "toast-stack";

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = String(html).trim();
  return t.content.firstElementChild;
}

export function toast({ tone = "ok", title, message, timeoutMs = 4500 } = {}) {
  const stack = document.getElementById(stackId);
  if (!stack) return;

  const safeTitle = title ? String(title) : "แจ้งเตือน";
  const safeMsg = message ? String(message) : "";

  const node = el(`
    <div class="toast toast--${tone}">
      <div class="toast__row">
        <p class="toast__title">${escapeHtml(safeTitle)}</p>
        <button class="toast__close" type="button" aria-label="ปิด">×</button>
      </div>
      <p class="toast__msg">${escapeHtml(safeMsg)}</p>
    </div>
  `);

  const closeBtn = node.querySelector(".toast__close");
  closeBtn?.addEventListener("click", () => node.remove());

  stack.prepend(node);
  if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
    window.setTimeout(() => node.remove(), timeoutMs);
  }
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
