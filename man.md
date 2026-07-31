---
layout: man
title: man
permalink: /man/
man_name: BLOG
man_section: 7
description: How this site is built, what the front matter means, and where the colours come from.
---

## NAME

blog — pwn and binary exploitation writeups, CTF notes, and the occasional
article

## SYNOPSIS

```
tre posts/[category/year/]
rg --tag TAG | rg --category CATEGORY
checksec POST
```

## DESCRIPTION

A Jekyll site. Markdown goes into `_posts/`, a static site comes out, and
GitHub Actions deploys it on push to `main`. There is no index to update, no
tag page to create and no table of contents to write; all of that is derived
from the files themselves.

The surface is a terminal because that is where the work being written about
happens. It is laid out as **tmux** panes with the author's real
`pane-border-format`, the prompts are the author's real two-line **zsh**
prompt, and the palette is generated from the same source that themes their
**nvim**, tmux and zsh.

## KEYS

The window numbers in the status bar are real bindings, not decoration.

```
C-b 1..N   select window        /   find a post
?          list these keys      t   cycle the theme
Esc        dismiss              j/k move within the finder
```

Where a browser has already claimed `C-b`, the browser wins — the unprefixed
keys reach everything the prefixed ones do.

## FILES

`_posts/`
: Published. One markdown file per post, `YYYY-MM-DD-name.md`.

`_drafts/`
: Unpublished. Listed on the front page under `tre drafts/`, never built.
  `bundle exec jekyll publish` moves one here into `_posts/`.

`_data/events.yml`
: CTF metadata keyed by the slug a post's `ctf.event` names, filled in once
  per event rather than once per challenge.

`_data/themes.yml`
: The only place a theme is named. A row with `sets:` is a live button in the
  picker; a row without one is defined but not yet generated for the web.

`assets/css/interdot-theme.css`
: Generated. Regenerate with `interdot generate` and copy it in.

## FRONT MATTER

Only `title` is required.

`categories`
: Becomes the post's directory in the index and its page under
  `/categories/`. The first one wins where there is more than one.

`tags`
: Each becomes a page under `/tags/`. Terms are linked by their slug, so
  `Heap Grooming` lives at `/tags/heap-grooming/`.

`toc`
: Draws the contents pane. On by default for posts.

`ctf`
: Turns on the `checksec` header block. Every key is optional: `event`,
  `category`, `remote`, `points`, `solves`, `difficulty`, `attachments`,
  `ctftime`, `with`.

`checksec`
: Arbitrary extra rows for that block, as a list of single-key maps. A row
  whose label matches a derived one replaces it; an empty value deletes it.

## DIAGNOSTICS

The build fails on a link that goes nowhere — a root-relative path with no file
behind it, a `#fragment` with no matching id, or the same id twice on one page.
Set `CHECK_LINKS=0` to downgrade that to a warning.

The OG card renderer fails the build if a card is missing, the wrong size, or
rendered in a fallback font.

## SEE ALSO

[interdotensional](https://github.com/embe221ed/interdotensional) — the
generator behind the palette.

tmux(1), zsh(1), tre(1), checksec(1)

## AUTHOR

Written by [embe221ed](https://github.com/embe221ed) of
[justCatTheFish](https://ctftime.org/team/33893).
