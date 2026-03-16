export function authScaffold({ title, subtitle, formHtml, asideVariant = "signin", footerHtml = "" }) {
  const aside = asideVariant === "dev"
    ? `
      <aside class="auth-hero">
        <div class="auth-hero__kicker">
          <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-link"></use></svg>
          <span>พอร์ทัลนักพัฒนา</span>
        </div>
        <h2 class="auth-hero__title">เชื่อมต่อ SSO ของคุณแบบ <em>มั่นใจ</em></h2>
        <p class="auth-hero__copy">
          เครื่องมือสำหรับทีมที่ต้องการความชัดเจน: คีย์, การผสานรวม, และบันทึกเหตุการณ์ความเสี่ยงในที่เดียว
        </p>
        <ul class="auth-hero__list">
          <li class="auth-hero__li"><span class="auth-hero__dot"></span><span>API keys พร้อม scope และการหมุนเวียน (rotate)</span></li>
          <li class="auth-hero__li"><span class="auth-hero__dot"></span><span>Integration presets สำหรับ OAuth/SSO</span></li>
          <li class="auth-hero__li"><span class="auth-hero__dot"></span><span>Logs + AI decisions ที่อ่านง่ายและอ้างอิงได้</span></li>
        </ul>
      </aside>
    `
    : `
      <aside class="auth-hero">
        <div class="auth-hero__kicker">
          <svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-shield"></use></svg>
          <span>Security-grade sign-in</span>
        </div>
        <h2 class="auth-hero__title">เข้าสู่ระบบแบบ <em>คุมได้</em> ทุกขั้นตอน</h2>
        <p class="auth-hero__copy">
          ออกแบบให้สแกนได้ภายในไม่กี่วินาที: สถานะชัด, ฟอร์มเข้าถึงได้, และข้อความผิดพลาดที่บอกทางแก้จริง
        </p>
        <ul class="auth-hero__list">
          <li class="auth-hero__li"><span class="auth-hero__dot"></span><span>Risk-based MFA (LOW/MEDIUM/HIGH) แบบโปร่งใส</span></li>
          <li class="auth-hero__li"><span class="auth-hero__dot"></span><span>ป้องกัน open redirect / CSRF ในทุกคำขอสำคัญ</span></li>
          <li class="auth-hero__li"><span class="auth-hero__dot"></span><span>โฟกัสและคอนทราสต์ที่เข้มพอสำหรับงานจริง</span></li>
        </ul>
      </aside>
    `;

  return `
    <div class="auth-grid">
      ${aside}
      <div class="card auth-card">
        <div class="card__header">
          <h1 class="card__title">${escapeHtml(title)}</h1>
          <p class="card__subtitle">${escapeHtml(subtitle)}</p>
        </div>
        <div class="card__inner stack stack--lg">
          <div id="status" hidden></div>
          ${formHtml}
          ${footerHtml}
        </div>
      </div>
    </div>
  `;
}

export function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

