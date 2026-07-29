# blog.embe221ed.dev

Jekyll. Markdown in, site out. Colors generated from the same palette that
themes my nvim, tmux and zsh.

## Publishing a post

```sh
vim _posts/2026-08-02-some-ctf-pwn.md
git commit -am "writeup: some-ctf pwn" && git push
```

That is the whole process. GitHub Actions builds and deploys on push to `main`.
Nothing else is required — no index to update, no table of contents to write,
no tag page to create. All of that is generated.

### Front matter

Only `title` is really required; the rest have sane defaults.

```yaml
---
title: madcore
date: 2022-07-15 05:00:00 +0200
categories: writeup
tags: pwn binexp googlectf     # space-separated string, or [a, b, c]
---
```

| key | default | notes |
|-----|---------|-------|
| `layout` | `post` | set in `_config.yml` defaults |
| `toc` | `true` | table of contents is built from your headings |
| `permalink` | `/posts/:title/` | **do not change** — the live URL depends on it |
| `categories` | none | generates `/categories/<name>/` |
| `tags` | none | generates `/tags/<name>/` per tag |
| `series` / `part` | none | reserved for multi-part writeups; nothing reads them yet |

Put `<!--more-->` after the opening paragraph to control the excerpt.

### Drafts

Anything in `_drafts/` is not built. Preview them with:

```sh
bundle exec jekyll serve --drafts --livereload
```

To advertise a draft on the homepage index without publishing it, add a row to
`_data/drafts.yml`. It renders greyed out with `-rw-------` mode bits.

### Images

Convention: `assets/img/<year>/<post-slug>/<name>.png`, referenced as

```markdown
![heap layout after the overflow](/assets/img/2026/some-ctf-pwn/heap.png)
```

Keep them reasonably sized — there is no image pipeline here on purpose.

## Local preview

```sh
bundle install          # once
bundle exec jekyll serve --livereload
```

You do **not** need Ruby to publish. Committing markdown is enough — CI builds
it. Press `.` on the GitHub repo to edit and commit from a browser.

## Structure

```
_posts/            the writeups
_drafts/           not built
_layouts/          default, home, post, page, archive
_includes/         tmux-bar
_data/             themes.yml, drafts.yml — homepage index data
assets/css/        interdot-theme.css (generated), main.css, syntax.css
assets/fonts/      Maple Mono, self-hosted (SIL OFL 1.1)
```

Two surfaces, deliberately different:

- **terminal** — homepage, about, archives. Full chrome: tmux status bar, the
  two-line zsh prompt, the post index as `ls -la`, an `interdot list` theme
  picker.
- **reader** — article pages. No chrome at all. One mono breadcrumb is the
  entire bridge back.

## Theming

`assets/css/interdot-theme.css` is **generated** — it is a block of CSS custom
properties named after `interdotensional`'s `tools.leaf.colors` role
vocabulary. Regenerate it with `interdot generate` and copy it in; never
generate it during deploy, because anything that can fail between "markdown
exists" and "it is live" is friction.

Every `var(--id-*)` in `main.css` carries a literal fallback. CSS has no
`StrictUndefined` — a renamed variable resolves to nothing, silently. Deleting
the generated file must still leave a readable site; test that occasionally.

## Things that will bite you

- `permalink: /posts/:title/` is load-bearing. The capitalised form of the
  madcore URL is the one that is indexed; lowercase 404s.
- `/feed.xml` **and** `/atom.xml` are both live and both have subscribers.
  `feed.xml` comes from `jekyll-feed`, `atom.xml` is hand-written. Keep both.
- Code block line numbers are drawn with CSS counters, not Rouge's text
  gutter — otherwise copying an exploit yields `1 from pwn import *`.
- Pin the Ruby version in CI. Never `latest`: Ruby ships a major every
  December 25th, and 4.0 broke Jekyll on release day.
