/* Theme toggle.
 *
 * The default is whatever `prefers-color-scheme` says; a stored choice
 * overrides it via data-theme on <html>, which the generated stylesheet
 * honours in both directions. The blocking snippet in <head> applies the
 * stored value before first paint — this file only handles interaction.
 */
(function () {
  "use strict";

  var root = document.documentElement;

  function systemTheme() {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function current() {
    return root.getAttribute("data-theme") || systemTheme();
  }

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("theme", theme);
    } catch (e) {
      /* private mode — the choice just won't persist */
    }
    sync();
  }

  function sync() {
    var theme = current();
    document.querySelectorAll("[data-theme-label]").forEach(function (el) {
      el.textContent = theme;
    });
    document.querySelectorAll("[data-set-theme]").forEach(function (el) {
      el.setAttribute("aria-pressed", String(el.dataset.setTheme === theme));
    });
  }

  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      apply(current() === "dark" ? "light" : "dark");
    });
  });

  document.querySelectorAll("[data-set-theme]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      apply(btn.dataset.setTheme);
    });
  });

  // Follow the OS while the visitor has not made an explicit choice.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
    if (!root.hasAttribute("data-theme")) sync();
  });

  sync();
})();
