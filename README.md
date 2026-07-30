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
| `checksec` | none | the header pane's rows, written by hand — see below |
| `ctf` | none | challenge metadata; adds rows to the same pane — see below |

Put `<!--more-->` after the opening paragraph to control the excerpt.

### The checksec block

The pane between the metadata line and the article is `checksec` output. Any
post can have one. A post that declares nothing renders **no pane at all** —
there is no empty state to look at.

```yaml
checksec:
  - Topic:  interdotensional
  - Status: in progress
```

One row per entry, in your order. The label is written once, as itself, and
whatever case you type is what renders. The dashes are optional — a plain
mapping does exactly the same thing, so a forgotten `-` costs you nothing:

```yaml
checksec:
  Topic:  interdotensional
  Status: in progress
```

A value may be a map when the row needs more than plain text:

| key | notes |
|-----|-------|
| `text` | the value. Defaults to `url`, so a bare `url:` is already a whole row |
| `url` | makes the value a link |
| `state` | `good` `bad` `warn` `note` — colours the VALUE. Labels are never coloured, the same way checksec never colours them |

```yaml
checksec:
  - Repo:
      text: embe221ed/interdotensional
      url:  https://github.com/embe221ed/interdotensional
  - Fuzzing:
      text:  no coverage yet
      state: bad
```

`state` is emphasis, never the message. **Write the word too** — `no coverage
yet` is red *and* says so, because a reader who cannot see the red still has to
get the point. An unrecognised `state` is dropped rather than guessed at.

A label with no value renders nothing.

#### Rows a `ctf:` block adds

Every key is optional; an absent one is simply a row you do not get.

| key | row | notes |
|-----|-----|-------|
| `event` | `Event` | a slug into `_data/events.yml`. An unlisted slug prints itself, so a one-off CTF never blocks the post |
| `category` | `Category` | the challenge's category on the scoreboard — not the post's `categories` |
| `remote` | `Remote` | turns red and gains `(offline)` once the event's `ends` date is past |
| `points` | `Points` | |
| `solves` | `Solves` | |
| `difficulty` | `Difficulty` | |
| `attachments` | `Files` | a list of `{name, url}`; `name` defaults to the url. They stack one per line |
| `ctftime` | `CTFtime` | the **task** id. The **event** id lives in `_data/events.yml` — different namespace, different URL |
| `with` | `Solved` | co-solvers. You are always the first name, and this row is always green |

`Ends` / `Ended` is the event's own date, out of `_data/events.yml`. It is not
the post's date, and that is deliberate — see the bite list.

#### Both at once

Derived rows come first, in the table's order; your own rows follow, in yours.
**A row you write beats a derived row with the same label** (case ignored),
which also makes an empty row the way to delete one:

```yaml
ctf:
  event:    googlectf-2022
  category: pwn
  remote:   madcore.2022.ctfcompetition.com:1337
checksec:
  Category: web              # replaces the derived `pwn`
  Remote:                    # deletes the derived Remote row outright
  Arch:     amd64-64-little  # a row nothing derives
```

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
_includes/         tmux-bar, ps1, ls-row, read-time, checksec
_data/             themes.yml, drafts.yml — homepage index data
                   events.yml — one row per CTF, shared by its writeups
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
- Code block line numbers are **off** on purpose. Rouge emits them as real
  text digits, so copying an exploit yields `1 from pwn import *`.
  `syntax.css` has the `user-select: none` mitigation ready if you want them
  back — flip `line_numbers` in `_config.yml`.
- Pin the Ruby version in CI. Never `latest`: Ruby ships a major every
  December 25th, and 4.0 broke Jekyll on release day.
- The checksec block prints the **event's** date and never the post's. The
  metadata line directly above it already carries the post date in the same
  `%Y-%m-%d` format, and a second copy two lines down says nothing new. So if
  the `Ends` / `Ended` row is missing, the thing to fix is `ends:` in
  `_data/events.yml` — nothing about the post will bring it back.
- An event missing from `_data/events.yml` is **not** an error: the slug prints
  as its own name. What you lose is the `Ends` / `Ended` row and the ability of
  the `Remote` row to ever go offline, because both are that file's `ends` key.
  A dead host advertised as live is the failure mode worth knowing about.
- `checksec:` labels are matched against derived rows by lowercasing them.
  `Remote`, `remote` and `REMOTE` are one label, and the last thing to claim it
  is the one you wrote.
