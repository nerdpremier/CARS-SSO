import { renderLogin } from "./views/login.js";
import { renderRegister } from "./views/register.js";
import { renderMfa } from "./views/mfa.js";
import { renderWelcome } from "./views/welcome.js";
import { renderDeveloper } from "./views/developer.js";
import { toast } from "./ui/toast.js";

const routes = [
  { path: "/", view: renderLogin },
  { path: "/login", view: renderLogin },
  { path: "/register", view: renderRegister },
  { path: "/mfa", view: renderMfa },
  { path: "/welcome", view: renderWelcome, guard: "auth" },
  { path: "/developer", view: renderDeveloper, guard: "auth" },
];

function match(pathname) {
  return routes.find((r) => r.path === pathname) || null;
}

export function navigate(path) {
  if (typeof path !== "string") return;
  if (!path.startsWith("/")) return;
  window.history.pushState({}, "", path);
  void renderRoute();
}

export function installLinkInterceptor() {
  document.addEventListener("click", (e) => {
    const a = e.target?.closest?.("a[data-link]");
    if (!a) return;
    const href = a.getAttribute("href") || "";
    if (!href.startsWith("/")) return;
    e.preventDefault();
    navigate(href);
  });
}

export async function renderRoute() {
  const outlet = document.getElementById("route");
  if (!outlet) return;
  outlet.setAttribute("aria-busy", "true");

  const pathname = window.location.pathname || "/";
  const r = match(pathname);
  if (!r) {
    outlet.innerHTML = `<div class="card"><div class="card__inner"><h1 class="card__title">ไม่พบหน้า</h1><p class="card__subtitle">URL นี้ไม่มีอยู่ในระบบ</p><div class="row row--mt-5"><a class="btn btn--ghost" href="/login" data-link>กลับไปเข้าสู่ระบบ</a></div></div></div>`;
    outlet.setAttribute("aria-busy", "false");
    return;
  }

  try {
    await r.view({ outlet });
  } catch (err) {
    toast({
      tone: "err",
      title: "โหลดหน้าไม่สำเร็จ",
      message: err?.message ? String(err.message) : "เกิดข้อผิดพลาดไม่ทราบสาเหตุ",
    });
    outlet.innerHTML = `<div class="card"><div class="card__inner"><h1 class="card__title">เกิดข้อผิดพลาด</h1><p class="card__subtitle">ลองรีเฟรช หรือกลับไปหน้าเข้าสู่ระบบ</p><div class="row row--mt-5"><a class="btn btn--ghost" href="/login" data-link>เข้าสู่ระบบ</a></div></div></div>`;
  } finally {
    outlet.setAttribute("aria-busy", "false");
  }
}

export function routerStart() {
  window.addEventListener("popstate", () => void renderRoute());
  void renderRoute();
}
