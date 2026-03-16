import { installLinkInterceptor, navigate, routerStart } from "./router.js";
import { toast } from "./ui/toast.js";
import { getSession, logout } from "./core/session.js";
import { setTheme, toggleTheme } from "./ui/theme.js";

function qs(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing #${id}`);
  return el;
}

async function initChrome() {
  const topbar = qs("topbar");
  const userPill = qs("user-pill");
  const userName = qs("user-name");
  const btnLogout = qs("btn-logout");
  const btnTheme = qs("theme-toggle");

  btnTheme.addEventListener("click", () => toggleTheme());

  btnLogout.addEventListener("click", async () => {
    try {
      await logout();
    } catch {}
    navigate("/login");
  });

  // Theme: default from localStorage, fallback to dark
  setTheme();

  // Session-driven chrome visibility (dashboard/portal only)
  const session = await getSession();
  const showChrome = Boolean(session.authenticated);
  topbar.hidden = !showChrome;
  userPill.hidden = !showChrome;
  btnLogout.hidden = !showChrome;
  if (session.authenticated && session.user) userName.textContent = session.user;
}

installLinkInterceptor();

// App bootstrap
Promise.resolve()
  .then(async () => {
    await initChrome();
    routerStart();
    document.body.classList.remove("app-pending");
  })
  .catch((err) => {
    // keep a minimal UX when something goes wrong
    toast({
      tone: "err",
      title: "เกิดข้อผิดพลาด",
      message: err?.message ? String(err.message) : "ไม่สามารถเริ่มต้นแอปได้",
    });
    // still attempt to start router for recovery
    routerStart();
  });

// Support external scripts calling navigate (optional)
window.CARS_NAVIGATE = (path) => navigate(path);
