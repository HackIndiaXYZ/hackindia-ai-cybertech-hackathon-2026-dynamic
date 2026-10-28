
(() => {
  "use strict";

  if (globalThis.__threatLensContentLoaded) return;
  globalThis.__threatLensContentLoaded = true;

  function checkPasswordForms() {
    const passwordFields = document.querySelectorAll(
      'input[type="password"]'
    );

    passwordFields.forEach((field) => {
      if (field.dataset.threatLensChecked === "true") return;

      field.dataset.threatLensChecked = "true";

      const form = field.closest("form");
      const isSecure = window.location.protocol === "https:";

      if (isSecure) return;

      const warning = document.createElement("div");

      warning.textContent =
        "ThreatLens AI Warning: This page is using HTTP. Avoid entering passwords or sensitive information.";

      warning.setAttribute("role", "alert");

      Object.assign(warning.style, {
        position: "relative",
        zIndex: "2147483647",
        background: "#7f1d1d",
        color: "#ffffff",
        padding: "12px",
        margin: "8px 0",
        border: "1px solid #ef4444",
        borderRadius: "8px",
        fontSize: "14px",
        lineHeight: "1.5",
        fontFamily: "Arial, sans-serif"
      });

      const target = form || field.parentElement;

      if (target) {
        target.insertBefore(warning, target.firstChild);
      }
    });
  }

  checkPasswordForms();

  const observer = new MutationObserver(() => {
    checkPasswordForms();
  });

  if (document.documentElement) {
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }
})();
