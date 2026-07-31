/* Keyboard navigation — the part of the tmux claim that was decoration.
 *
 * The status bar has always drawn `1:home 2:categories 3:tags …`. Those numbers
 * came from the window's position in _data/windows.yml, exactly like tmux's
 * `renumber-windows on`, and did nothing. This makes them do what they say.
 *
 * BINDINGS
 *   C-b then 1..9   select window          (prefix, as in the real config)
 *   /               find a post
 *   ?               keybinding menu
 *   t               cycle the theme
 *   Escape          dismiss whatever is open
 *
 * The prefix is real: C-b arms, the status bar shows the pending indicator, and
 * the next key either selects a window or cancels. It times out after three
 * seconds, because a prefix that stays armed forever eats the next thing you
 * type into the page.
 *
 * WHY THE WINDOW LIST IS READ FROM THE DOM. The bar is rendered from
 * _data/windows.yml. Reading the rendered links back means adding, removing or
 * reordering a window in that file changes the bindings too, with nothing here
 * to keep in sync — the same rule the numbers themselves follow.
 *
 * C-b IS TAKEN IN A BROWSER on some platforms, and where it is, the browser
 * wins. That is the correct outcome: this is a site, not a terminal emulator,
 * and stealing a browser binding to complete a metaphor is a bad trade. The
 * unprefixed keys carry the same navigation for anyone whose C-b is spoken for,
 * and `?` lists them.
 */
(function () {
  "use strict";

  var root = document.documentElement;

  /* Typing must never trigger a binding. contentEditable is included because a
   * comment box or an editable demo would otherwise swallow its own letters. */
  function typing(el) {
    if (!el) return false;
    if (el.isContentEditable) return true;
    var tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
  }

  /* ---- windows, read back out of the rendered status bar ----------------- */
  var winEls = [].slice.call(document.querySelectorAll(".tmux__win"));
  var windows = winEls.map(function (a) {
    return { url: a.getAttribute("href"), name: a.textContent.replace(/^\d+:/, "") };
  });

  /* ---- overlay plumbing -------------------------------------------------- */
  var layer = document.createElement("div");
  layer.className = "layer";
  layer.hidden = true;
  document.body.appendChild(layer);

  var openKind = null;      /* null | "menu" | "find" */
  var lastFocus = null;

  function close() {
    if (!openKind) return;
    openKind = null;
    layer.hidden = true;
    layer.innerHTML = "";
    root.classList.remove("is-layered");
    if (lastFocus && lastFocus.focus) lastFocus.focus();
    lastFocus = null;
  }

  function open(kind, node) {
    if (openKind) close();
    lastFocus = document.activeElement;
    openKind = kind;
    layer.innerHTML = "";
    layer.appendChild(node);
    layer.hidden = false;
    root.classList.add("is-layered");
  }

  layer.addEventListener("mousedown", function (e) {
    if (e.target === layer) close();
  });

  /* ---- the prefix indicator --------------------------------------------- */
  var pfx = document.querySelector("[data-prefix]");
  var armed = false, armTimer = null;

  function arm() {
    armed = true;
    if (pfx) pfx.classList.add("is-on");
    clearTimeout(armTimer);
    armTimer = setTimeout(disarm, 3000);
  }
  function disarm() {
    armed = false;
    if (pfx) pfx.classList.remove("is-on");
    clearTimeout(armTimer);
  }

  /* ---- KEY-04: the keybinding menu, in the rounded+pink tier ------------- */
  function menuNode() {
    var box = document.createElement("div");
    box.className = "menu menu--keys";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.setAttribute("aria-label", "Keyboard shortcuts");
    box.tabIndex = -1;

    var rows = [["C-b 1-" + Math.min(windows.length, 9), "select window"]];
    windows.forEach(function (w, i) {
      if (i < 9) rows.push(["  C-b " + (i + 1), w.name]);
    });
    rows.push([null, null]);            /* separator */
    rows.push(["/", "find a post"]);
    rows.push(["t", "cycle theme"]);
    rows.push(["?", "this menu"]);
    rows.push(["Esc", "dismiss"]);

    rows.forEach(function (r, i) {
      if (r[0] === null) {
        var sep = document.createElement("div");
        sep.className = "menu__sep";
        box.appendChild(sep);
        return;
      }
      var row = document.createElement("div");
      row.className = "menu__row" + (i === 0 ? " is-sel" : "");
      var k = document.createElement("span");
      k.className = "menu__key";
      k.textContent = r[0];
      var d = document.createElement("span");
      d.textContent = r[1];
      row.appendChild(k);
      row.appendChild(d);
      box.appendChild(row);
    });
    return box;
  }

  /* ---- FIND-01: the finder ---------------------------------------------- */
  var index = null, indexPromise = null;

  function loadIndex() {
    if (index) return Promise.resolve(index);
    if (indexPromise) return indexPromise;
    var base = document.documentElement.getAttribute("data-baseurl") || "";
    indexPromise = fetch(base + "/search.json", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (j) { index = j; return index; })
      .catch(function () { index = []; return index; });
    return indexPromise;
  }

  /* Subsequence match over "title category tags date". Score rewards runs that
   * are contiguous and hits that land in the title, so typing `mad` puts
   * `madcore` above a post merely tagged with something containing m, a, d. */
  function score(query, entry) {
    var hay = (entry.t + " " + entry.c + " " + (entry.g || []).join(" ") + " " + entry.d).toLowerCase();
    var q = query.toLowerCase().replace(/\s+/g, "");
    if (!q) return { hit: true, score: 0, marks: [] };
    var i = 0, s = 0, last = -2, marks = [];
    for (var j = 0; j < q.length; j++) {
      var at = hay.indexOf(q[j], i);
      if (at < 0) return { hit: false };
      if (at < entry.t.length) marks.push(at);
      s += (at === last + 1 ? 0 : 6) + (at >= entry.t.length ? 4 : 0);
      last = at; i = at + 1;
    }
    return { hit: true, score: s, marks: marks };
  }

  function rank(query, entries) {
    return entries
      .map(function (e) { var m = score(query, e); return { e: e, m: m }; })
      .filter(function (r) { return r.m.hit; })
      .sort(function (a, b) {
        if (a.m.score !== b.m.score) return a.m.score - b.m.score;
        return a.e.d < b.e.d ? 1 : -1;            /* ties: newest first */
      });
  }

  function markTitle(title, marks) {
    var set = {}, out = document.createDocumentFragment();
    marks.forEach(function (k) { set[k] = 1; });
    for (var i = 0; i < title.length; i++) {
      if (set[i]) {
        var em = document.createElement("em");
        em.textContent = title[i];
        out.appendChild(em);
      } else {
        out.appendChild(document.createTextNode(title[i]));
      }
    }
    return out;
  }

  function finderNode() {
    var box = document.createElement("div");
    box.className = "fz";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.setAttribute("aria-label", "Find a post");

    box.innerHTML =
      '<div class="fz__in">' +
        '<span class="fz__caret" aria-hidden="true">❯</span>' +
        '<input class="fz__field" type="text" autocomplete="off" spellcheck="false"' +
        ' aria-label="Search posts" aria-controls="fz-list">' +
        '<span class="fz__count" data-count aria-live="polite"></span>' +
      '</div>' +
      '<ul class="fz__list" id="fz-list" role="listbox" aria-label="Results"></ul>';

    var input = box.querySelector(".fz__field");
    var list = box.querySelector(".fz__list");
    var count = box.querySelector("[data-count]");
    var rows = [], sel = 0;

    function draw() {
      var res = rank(input.value.trim(), index || []);
      rows = res;
      sel = 0;
      count.textContent = res.length + "/" + (index ? index.length : 0);
      list.innerHTML = "";
      if (!res.length) {
        var none = document.createElement("li");
        none.className = "fz__none";
        none.textContent = index && index.length ? "no matches" : "nothing published yet";
        list.appendChild(none);
        return;
      }
      res.forEach(function (r, i) {
        var li = document.createElement("li");
        li.className = "fz__row" + (i === 0 ? " is-sel" : "");
        li.setAttribute("role", "option");
        li.setAttribute("aria-selected", i === 0 ? "true" : "false");
        var cat = document.createElement("span");
        cat.className = "fz__cat";
        cat.textContent = r.e.c || "—";
        var name = document.createElement("span");
        name.className = "fz__name";
        name.appendChild(markTitle(r.e.t, r.m.marks));
        var date = document.createElement("span");
        date.className = "fz__date";
        date.textContent = r.e.d;
        li.appendChild(cat); li.appendChild(name); li.appendChild(date);
        li.addEventListener("mousedown", function (ev) {
          ev.preventDefault();
          window.location.href = r.e.u;
        });
        list.appendChild(li);
      });
    }

    function move(d) {
      if (!rows.length) return;
      var kids = list.children;
      kids[sel].classList.remove("is-sel");
      kids[sel].setAttribute("aria-selected", "false");
      sel = (sel + d + rows.length) % rows.length;
      kids[sel].classList.add("is-sel");
      kids[sel].setAttribute("aria-selected", "true");
      kids[sel].scrollIntoView({ block: "nearest" });
    }

    input.addEventListener("input", draw);
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown" || (e.ctrlKey && e.key === "n")) { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp" || (e.ctrlKey && e.key === "p")) { e.preventDefault(); move(-1); }
      else if (e.key === "Enter" && rows[sel]) { e.preventDefault(); window.location.href = rows[sel].e.u; }
      else if (e.key === "Escape") { e.preventDefault(); close(); }
    });

    loadIndex().then(function () { draw(); input.focus(); });
    setTimeout(function () { input.focus(); }, 0);
    return box;
  }

  /* ---- key handling ------------------------------------------------------ */
  document.addEventListener("keydown", function (e) {
    if (e.defaultPrevented) return;

    if (e.key === "Escape" && openKind) { e.preventDefault(); close(); return; }
    if (typing(e.target)) return;
    if (e.altKey || e.metaKey) return;

    /* prefix */
    if (e.ctrlKey && (e.key === "b" || e.key === "B")) {
      e.preventDefault();
      armed ? disarm() : arm();
      return;
    }
    if (armed) {
      var n = parseInt(e.key, 10);
      disarm();
      if (n >= 1 && n <= windows.length) {
        e.preventDefault();
        window.location.href = windows[n - 1].url;
      }
      return;
    }
    if (e.ctrlKey) return;

    if (e.key === "/") { e.preventDefault(); open("find", finderNode()); return; }
    if (e.key === "?") { e.preventDefault(); openKind === "menu" ? close() : open("menu", menuNode()); return; }
    if (e.key === "t") {
      var btn = document.querySelector("[data-theme-toggle]");
      if (btn) { e.preventDefault(); btn.click(); }
    }
  });

  /* On a narrow screen the window list is one scrolling line, so the current
   * window can start off-screen — `6:about` while the list shows 1 through 4.
   * Nudged into view without scrolling the page itself. */
  var current = document.querySelector('.tmux__win[aria-current="page"]');
  if (current && current.scrollIntoView) {
    current.scrollIntoView({ block: "nearest", inline: "nearest" });
  }

  /* The 404 needs the same index and the same ranking to suggest a near miss,
   * and a second copy of a scoring function is a second thing to get wrong.
   * This is the only export; everything else stays private to the file. */
  window.blogSearch = { load: loadIndex, rank: rank };

  /* The bar advertises the menu once the bindings actually exist. Written by
   * script rather than by the template so it can never claim a keyboard on a
   * page where this file failed to load. */
  var hint = document.querySelector("[data-keyhint]");
  if (hint) {
    hint.hidden = false;
    hint.addEventListener("click", function () {
      openKind === "menu" ? close() : open("menu", menuNode());
    });
  }
})();
