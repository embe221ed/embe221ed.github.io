/* Theme mode.
 *
 * Three states, not two: auto, light, dark. Auto is the default and it is
 * REACHABLE — that is the whole point of this file existing rather than a
 * two-way flip.
 *
 * The stylesheet already follows the device on its own: interdot-theme.css
 * scopes its dark block to `@media (prefers-color-scheme: dark) :root:not([data-theme])`,
 * so with no attribute set the OS decides and nothing here has to run. What an
 * override does is pin `data-theme` on <html>, which the generated sheet
 * honours in both directions.
 *
 * The bug this replaces: a two-way toggle wrote localStorage on every press and
 * never cleared it, and the blocking snippet in <head> re-applied it before
 * first paint. So the first press was a one-way door — the site stopped
 * following the device forever, on every visit, with no control that could put
 * it back. Auto was the default state and simultaneously unreachable.
 *
 * `interdot toggle` in the author's dotfiles flips between a theme's light and
 * dark pair and has no auto, because a terminal has no visitor whose OS already
 * answered the question. A website does, so the third state is a web-specific
 * necessity rather than an infidelity to the tool.
 */
(function () {
  "use strict";

  var root = document.documentElement;
  var KEY = "theme";
  var MODES = ["auto", "light", "dark"];
  var media = window.matchMedia("(prefers-color-scheme: dark)");

  /* The mode the visitor has chosen. Anything unrecognised — a value from an
   * older build, a hand-edited key — reads as auto rather than being trusted. */
  function mode() {
    var stored;
    try {
      stored = localStorage.getItem(KEY);
    } catch (e) {
      /* private mode: no storage, so the mode is whatever the attribute says */
      return root.getAttribute("data-theme") || "auto";
    }
    return MODES.indexOf(stored) > 0 ? stored : "auto";
  }

  /* What the page is actually painted as, which in auto is the device's answer. */
  function resolved() {
    var m = mode();
    return m === "auto" ? (media.matches ? "dark" : "light") : m;
  }

  function apply(next) {
    if (next === "auto") {
      /* Removing the attribute is what hands control back to the media query.
       * Setting data-theme to the current system value would LOOK identical and
       * would then stop tracking the device the moment it changed. */
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", next);
    }
    try {
      if (next === "auto") {
        localStorage.removeItem(KEY);
      } else {
        localStorage.setItem(KEY, next);
      }
    } catch (e) {
      /* the choice just will not survive the tab */
    }
    sync();
  }

  function sync() {
    var m = mode();
    var r = resolved();
    /* The label names the MODE, not the paint. In auto it has to read `auto`,
     * or the one state that matters is the one the reader cannot see. */
    document.querySelectorAll("[data-theme-label]").forEach(function (el) {
      el.textContent = m;
    });
    /* The picker's rows are explicit setters, so they press against the
     * RESOLVED theme: in auto on a dark device, the dark row is the live one. */
    document.querySelectorAll("[data-set-theme]").forEach(function (el) {
      el.setAttribute("aria-pressed", String(el.dataset.setTheme === r));
    });
  }

  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      apply(MODES[(MODES.indexOf(mode()) + 1) % MODES.length]);
    });
  });

  document.querySelectorAll("[data-set-theme]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      apply(btn.dataset.setTheme);
    });
  });

  /* In auto the paint changes under us when the device flips — at sunset, on a
   * schedule, by hand. Nothing needs repainting (the media query does that),
   * but the picker's pressed row moved and has to be told. */
  media.addEventListener("change", sync);

  sync();
})();
