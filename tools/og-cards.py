#!/usr/bin/env python3
"""REACH-01 — render the Open Graph cards, and refuse to ship a broken one.

Runs after `jekyll build` and before upload-pages-artifact. It screenshots every
page _plugins/og_cards.rb generated under _site/cards/ into
_site/assets/og/<slug>.png at exactly 1200x630, then asserts that every og:image
the built HTML advertises actually exists.

That last part is the point, not a nicety. A post whose og:image 404s renders
WORSE in a Discord embed than a post with no og:image at all — the client draws a
broken-image slot instead of falling back to the summary card. So every failure
here is fatal and loud: a visible red deploy is the cheap outcome, and a silently
grey-rectangled writeup is the expensive one.

WHY A BROWSER AND NOT A RASTERISER
    The card is a real page built from the site's real main.css and the site's
    real self-hosted Maple Mono. An SVG template or a canvas library would be a
    second description of the same design, free to drift from the first the next
    time the pane border or the status line changes. This one cannot drift.

WHY CDP AND NOT `chrome --headless --screenshot`
    Because --screenshot no longer works. Measured here on Chrome 151: the
    process starts, loads the page, and then hangs forever without writing a
    file — same for --dump-dom and --print-to-pdf. Those "headless commands" were
    deprecated when old headless was removed in Chrome 132 and survive only in
    chrome-headless-shell, which is not on a GitHub runner. Building the step on
    them would be building on the exact flakiness this task was warned about:
    they fail by hanging, and a hang in CI reads as an infrastructure blip rather
    than as a broken card.

    Page.captureScreenshot over the DevTools protocol is what every browser
    automation tool actually uses, and it is stable across every Chrome that has
    shipped this decade. The transport is --remote-debugging-pipe: NUL-delimited
    JSON on fds 3 and 4, which needs no websocket library and no open port. Total
    third-party dependencies for this file: zero. It is stdlib Python and a
    browser.

WHY A LOCAL HTTP SERVER
    main.css asks for /assets/fonts/MapleMono-Regular.woff2 — root-absolute,
    because that is what the deployed site serves. Under file:// that resolves to
    the filesystem root and 404s, and the card would come out set in whatever
    mono the runner happens to have, which is a card that lies about the site.
    So _site is served over http on a loopback port. The server is also the
    witness: it records every request it answers, and the run fails unless both
    woff2 files were fetched with a 200.

Environment:
    SITE_DIR    built site to read and write (default: _site)
    CHROME_BIN  browser to use; otherwise the usual names are searched
"""

from __future__ import annotations

import base64
import functools
import glob
import http.server
import json
import os
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# Must agree with OgCards::WIDTH / OgCards::HEIGHT in _plugins/og_cards.rb, which
# is what seo-tag publishes as og:image:width and og:image:height. A card whose
# pixels disagree with its own metadata is a card that gets letterboxed.
CARD_W = 1200
CARD_H = 630

SITE = Path(os.environ.get("SITE_DIR", "_site")).resolve()
OG_DIR = SITE / "assets" / "og"

# The two faces the card actually sets text in. Italic is never used on a card,
# so requiring it would fail a build for a file nothing asked for.
REQUIRED_FONTS = ("/assets/fonts/MapleMono-Regular.woff2",
                  "/assets/fonts/MapleMono-Bold.woff2")

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class Failure(Exception):
    """A condition that must stop the deploy."""


# ----------------------------------------------------------------------------
# the site under test
# ----------------------------------------------------------------------------

OG_IMAGE_RE = re.compile(rb'<meta\s+property="og:image"\s+content="([^"]+)"')
OG_URL_RE = re.compile(rb'<meta\s+property="og:url"\s+content="([^"]+)"')


def host_of(url: str) -> str:
    return re.sub(r"^[a-z]+://([^/]*).*$", r"\1", url)


def advertised_images() -> dict[str, Path]:
    """Every og:image the built site points at, mapped to where it must land.

    Read out of the HTML rather than recomputed from the post list, because the
    HTML is what actually ships: whatever a scraper will fetch is exactly what
    gets asserted. Only same-host images are claimed — an author who points
    og:image at a CDN is not this script's business, and its absence from _site
    is not a fault.
    """
    found: dict[str, Path] = {}
    for html in SITE.rglob("*.html"):
        blob = html.read_bytes()
        img = OG_IMAGE_RE.search(blob)
        if not img:
            continue
        img_url = img.group(1).decode("utf-8", "replace")
        page = OG_URL_RE.search(blob)
        page_host = host_of(page.group(1).decode()) if page else ""
        if page_host and host_of(img_url) != page_host:
            continue
        path = re.sub(r"^[a-z]+://[^/]*", "", img_url)
        found[img_url] = SITE / path.lstrip("/")
    return found


def card_pages() -> list[str]:
    """Slugs of the card pages the Jekyll generator produced."""
    root = SITE / "cards"
    if not root.is_dir():
        return []
    return sorted(p.parent.name for p in root.glob("*/index.html"))


# ----------------------------------------------------------------------------
# the server
# ----------------------------------------------------------------------------

class Recorder(http.server.SimpleHTTPRequestHandler):
    """A static server that keeps the access log in memory.

    The log is the proof that the webfont was really fetched. Chrome only
    downloads a woff2 when a rule it is about to paint with actually needs it, so
    a 200 on MapleMono-Bold.woff2 is a statement from the renderer that the card
    is set in Maple Mono and not in a system fallback.
    """

    served: list[tuple[str, int]] = []

    def log_request(self, code="-", size="-"):  # noqa: D102 - stdlib hook
        try:
            Recorder.served.append((self.path, int(code)))
        except (TypeError, ValueError):
            Recorder.served.append((self.path, -1))

    def log_message(self, fmt, *args):
        pass  # the recorder above is the log; stderr noise helps nobody


def serve(root: Path) -> tuple[http.server.ThreadingHTTPServer, int]:
    handler = functools.partial(Recorder, directory=str(root))
    # Port 0: the OS picks a free one. A hardcoded port is a race against
    # anything else on the runner and a guaranteed conflict on a dev machine
    # that already has `jekyll serve` up.
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


# ----------------------------------------------------------------------------
# the browser
# ----------------------------------------------------------------------------

CANDIDATES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    # Not on a runner, but this is what a Playwright install leaves behind, so a
    # developer checking a card locally does not have to install a browser.
    "chrome-headless-shell",
)

CACHE_GLOBS = (
    "~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome",
    "~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell",
)


def find_browser() -> str:
    explicit = os.environ.get("CHROME_BIN")
    if explicit:
        if not (Path(explicit).is_file() and os.access(explicit, os.X_OK)):
            raise Failure(f"CHROME_BIN is set to {explicit!r}, which is not an executable file.")
        return explicit

    for name in CANDIDATES:
        found = shutil.which(name)
        if found:
            return found

    for pattern in CACHE_GLOBS:
        hits = sorted(glob.glob(os.path.expanduser(pattern)))
        if hits:
            return hits[-1]

    raise Failure(
        "No Chrome found. Tried $CHROME_BIN and then "
        + ", ".join(CANDIDATES)
        + " on PATH.\n"
        "        ubuntu-latest ships Google Chrome; if this fired on a GitHub runner "
        "the image changed and\n        the workflow needs a browser-install step, "
        "not a retry."
    )


class Chrome:
    """A browser driven over --remote-debugging-pipe.

    Commands go out on fd 3 and replies come back on fd 4, one JSON object per
    NUL byte. Both directions are a plain pipe, so there is no port to collide
    with, no websocket handshake to implement, and nothing to leak if the process
    is killed.
    """

    def __init__(self, binary: str, profile: Path):
        # /bin/sh does the fd shuffle instead of a preexec_fn. Chrome insists on
        # exactly fds 3 and 4, and CPython runs preexec_fn BEFORE it closes the
        # child's inherited descriptors — verified here, the dup'd fd 4 was
        # closed again before exec and Chrome exited with "Remote debugging pipe
        # file descriptors are not open". A shell redirection happens after all
        # of that and cannot be reordered. `exec "$@"` replaces the shell, so the
        # pid below really is the browser's.
        to_browser_r, self._to_browser = os.pipe()
        self._from_browser, from_browser_w = os.pipe()
        os.set_inheritable(to_browser_r, True)
        os.set_inheritable(from_browser_w, True)

        argv = [
            binary,
            "--headless=new",
            "--remote-debugging-pipe",
            f"--user-data-dir={profile}",
            # A runner is often a container, where the namespace sandbox cannot
            # be set up and Chrome refuses to start without this.
            "--no-sandbox",
            "--disable-gpu",
            # /dev/shm is 64MB in a container and Chrome will crash rather than
            # fall back on its own.
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            # None of this run is a browsing session: no update pings, no GCM
            # registration, no field trials phoning home. Cuts about a second and
            # a screenful of ERROR lines from a build log.
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-extensions",
            "--metrics-recording-only",
            # The card is a colour asset. Pinning the profile keeps the PNG the
            # same on a runner as on the machine it was designed on.
            "--force-color-profile=srgb",
            "--hide-scrollbars",
            "about:blank",
        ]
        shuffle = 'exec 3<&%d 4>&%d; exec "$@"' % (to_browser_r, from_browser_w)
        self.proc = subprocess.Popen(
            ["/bin/sh", "-c", shuffle, "sh"] + argv,
            pass_fds=(to_browser_r, from_browser_w),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.close(to_browser_r)
        os.close(from_browser_w)

        self._buf = b""
        self._id = 0

    # -- transport ---------------------------------------------------------

    def send(self, method: str, params: dict | None = None, session: str | None = None) -> int:
        self._id += 1
        msg: dict = {"id": self._id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        os.write(self._to_browser, json.dumps(msg).encode() + b"\0")
        return self._id

    def _recv(self, deadline: float) -> dict:
        while b"\0" not in self._buf:
            ready, _, _ = select.select([self._from_browser], [], [], max(0.0, deadline - time.time()))
            if not ready:
                raise Failure("Chrome stopped answering on the debugging pipe.")
            chunk = os.read(self._from_browser, 1 << 16)
            if not chunk:
                raise Failure(f"Chrome exited (status {self.proc.poll()}) mid-conversation.")
            self._buf += chunk
        raw, _, self._buf = self._buf.partition(b"\0")
        return json.loads(raw)

    def call(self, method: str, params: dict | None = None, session: str | None = None,
             timeout: float = 45.0) -> dict:
        """Send a command and return its result, discarding events in between."""
        want = self.send(method, params, session)
        deadline = time.time() + timeout
        while True:
            msg = self._recv(deadline)
            if msg.get("id") != want:
                continue
            if "error" in msg:
                raise Failure(f"{method} failed: {msg['error']}")
            return msg.get("result", {})

    def close(self):
        try:
            self.send("Browser.close")
            self.proc.wait(timeout=15)
        except Exception:
            self.proc.kill()
        finally:
            for fd in (self._to_browser, self._from_browser):
                try:
                    os.close(fd)
                except OSError:
                    pass


# The page-side check, run after the navigation settles. Three independent
# statements, because each one alone has a way of being true about a broken card:
#
#   dom      the card really rendered — an ERR_CONNECTION_REFUSED interstitial is
#            also 1200x630 and also a valid PNG, and this is the only thing that
#            tells them apart. It happened during development, which is why the
#            check exists.
#   faces    the browser's own font registry says both Maple Mono faces reached
#            status "loaded" — not "requested", not "unloaded".
#   widths   a measurement rather than a claim: the same string measured in
#            "Maple Mono" and in a family that certainly does not exist. If the
#            webfont had silently failed, both would resolve to the same fallback
#            and the two widths would be identical.
PROBE_JS = r"""
document.fonts.ready.then(() => {
  const title = document.querySelector('.card__title');
  const pane  = document.querySelector('.pane__title');
  const ctx   = document.createElement('canvas').getContext('2d');
  const probe = 'ABCDEFGHIJ0123456789';
  ctx.font = '100px "Maple Mono"';           const maple    = ctx.measureText(probe).width;
  ctx.font = '100px "NoSuchFamilyEverXYZ"';  const fallback = ctx.measureText(probe).width;
  return JSON.stringify({
    dom:   { title: title ? title.textContent.trim() : null,
             pane:  pane ? pane.textContent.trim() : null,
             ready: document.readyState },
    faces: [...document.fonts].map(f => [f.family, String(f.weight), f.status]),
    width: { maple: maple, fallback: fallback },
  });
});
"""


def probe_and_shoot(chrome: Chrome, url: str, out: Path) -> dict:
    """Load one card, prove it is the card, and write its PNG."""
    target = chrome.call("Target.createTarget", {"url": "about:blank"})["targetId"]
    session = chrome.call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
    try:
        # The screenshot size comes from the emulation override, not from
        # --window-size: the override is what Page.captureScreenshot clips to, so
        # the PNG is 1200x630 whatever window the platform decided to give us.
        chrome.call("Emulation.setDeviceMetricsOverride", {
            "width": CARD_W, "height": CARD_H, "deviceScaleFactor": 1, "mobile": False,
        }, session)
        # card.html already pins the polarity with data-theme="light", and
        # interdot-theme.css honours that over prefers-color-scheme in both
        # directions. This is the second lock on the same door: a PNG has no
        # theme toggle, so the ONE thing that must not depend on the runner's
        # environment is which theme the card came out in. Reduced motion is set
        # for the same reason — a shot taken mid-animation is a shot that differs
        # between runs, and the site promises that guard anyway.
        chrome.call("Emulation.setEmulatedMedia", {"features": [
            {"name": "prefers-color-scheme", "value": "light"},
            {"name": "prefers-reduced-motion", "value": "reduce"},
        ]}, session)
        chrome.call("Page.enable", None, session)
        chrome.call("Page.navigate", {"url": url}, session)

        # Polled, not event-driven. Page.loadEventFired is ambiguous here: the
        # target starts on about:blank, which fires its own load event, and
        # waiting for "a" load event caught that one and evaluated against an
        # empty document. Asking the page whether it is finished has no such
        # ordering hazard.
        deadline = time.time() + 30
        probe = None
        while time.time() < deadline:
            res = chrome.call("Runtime.evaluate", {
                "expression": PROBE_JS, "awaitPromise": True, "returnByValue": True,
            }, session)
            value = res.get("result", {}).get("value")
            if isinstance(value, str):
                probe = json.loads(value)
                if probe["dom"]["ready"] == "complete" and probe["dom"]["title"]:
                    break
            time.sleep(0.2)

        if probe is None or not probe["dom"]["title"]:
            raise Failure(f"{url} never became a card page: {probe!r}")

        shot = chrome.call("Page.captureScreenshot", {"format": "png"}, session)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(base64.b64decode(shot["data"]))
        return probe
    finally:
        # Swallowed on purpose: if the browser has already died, the interesting
        # exception is the one on its way out, not this one. Leaking a tab in a
        # process that is about to be closed costs nothing.
        try:
            chrome.call("Target.closeTarget", {"targetId": target}, timeout=10)
        except Failure:
            pass


# ----------------------------------------------------------------------------
# assertions
# ----------------------------------------------------------------------------

def check_png(path: Path) -> tuple[int, int, int]:
    if not path.is_file():
        raise Failure(f"{path} was never written.")
    blob = path.read_bytes()
    if not blob:
        raise Failure(f"{path} is empty.")
    if blob[:8] != PNG_MAGIC:
        raise Failure(f"{path} is not a PNG.")
    w, h = struct.unpack(">II", blob[16:24])
    if (w, h) != (CARD_W, CARD_H):
        raise Failure(f"{path} is {w}x{h}, not {CARD_W}x{CARD_H} — og:image:width would be a lie.")
    return w, h, len(blob)


def check_fonts(probe: dict, slug: str) -> None:
    loaded = {(fam, weight) for fam, weight, status in probe["faces"] if status == "loaded"}
    for weight in ("400", "700"):
        if ("Maple Mono", weight) not in loaded:
            raise Failure(
                f"{slug}: Maple Mono {weight} is not loaded — the card is set in a system "
                f"fallback and lies about the site.\n        document.fonts said: {probe['faces']}"
            )
    maple, fallback = probe["width"]["maple"], probe["width"]["fallback"]
    if abs(maple - fallback) < 0.5:
        raise Failure(
            f"{slug}: text measured {maple}px in Maple Mono and {fallback}px in a family that "
            "does not exist.\n        Identical widths mean both resolved to the same fallback face."
        )


def main() -> int:
    if not SITE.is_dir():
        raise Failure(f"{SITE} does not exist. Run `bundle exec jekyll build` first.")

    slugs = card_pages()
    wanted = advertised_images()

    if not slugs:
        raise Failure(
            f"No card pages under {SITE / 'cards'}. _plugins/og_cards.rb did not run, or every "
            "post already carries its own `image:`."
        )
    if len(wanted) != len(slugs):
        raise Failure(
            f"{len(slugs)} card page(s) but {len(wanted)} og:image tag(s) in the built HTML. "
            "The generator and the pages disagree about which posts have cards."
        )

    binary = find_browser()
    httpd, port = serve(SITE)
    profile = Path(tempfile.mkdtemp(prefix="og-cards-"))
    chrome = Chrome(binary, profile)

    print(f"og-cards: {binary}")
    print(f"og-cards: serving {SITE} on 127.0.0.1:{port}")

    try:
        for slug in slugs:
            url = f"http://127.0.0.1:{port}/cards/{slug}/"
            out = OG_DIR / f"{slug}.png"
            probe = probe_and_shoot(chrome, url, out)
            check_fonts(probe, slug)
            w, h, size = check_png(out)
            print(f"og-cards: {slug}.png  {w}x{h}  {size:,} bytes  "
                  f"title={probe['dom']['title']!r}  pane={probe['dom']['pane']!r}")
    finally:
        chrome.close()
        httpd.shutdown()
        shutil.rmtree(profile, ignore_errors=True)

    # Chrome fetches a webfont only when it is about to paint with it, so a 200
    # on both files is the renderer's own testimony. Belt to the braces of
    # document.fonts above: this one would still catch a card that loaded the
    # face from a stale disk cache rather than from the site being shipped.
    served = {path for path, code in Recorder.served if code == 200}
    missing = [f for f in REQUIRED_FONTS if f not in served]
    if missing:
        raise Failure(
            "The card never fetched " + ", ".join(missing) + ".\n"
            "        Either main.css moved the font files or card.css is pointing at the old path."
        )

    # The assertion that matters most, and the last one on purpose: whatever the
    # <head> tells a scraper to fetch has to be sitting in the artifact.
    for url, path in sorted(wanted.items()):
        check_png(path)
        print(f"og-cards: {url} -> {path.relative_to(SITE)} ok")

    print(f"og-cards: {len(wanted)} card(s) rendered and verified.")
    return 0


def banner(reason: str) -> None:
    sys.stdout.flush()
    print("\n" + "=" * 72, file=sys.stderr)
    print("OG CARD RENDER FAILED — refusing to deploy.", file=sys.stderr)
    print(f"  {reason}", file=sys.stderr)
    print("A post whose og:image 404s embeds worse than a post with none.", file=sys.stderr)
    print("=" * 72, file=sys.stderr)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as err:
        banner(str(err))
        sys.exit(1)
    except Exception:  # noqa: BLE001 - nothing here is worth continuing past
        # Anything unplanned — a browser that segfaults, a full disk, a CDP
        # method that changed shape — ends the same way as a planned failure.
        # The traceback goes to the log for whoever has to fix it; the exit code
        # is what stops the artifact from going out with a hole in it.
        import traceback
        traceback.print_exc()
        banner("Unhandled error above; the cards were not verified.")
        sys.exit(1)
