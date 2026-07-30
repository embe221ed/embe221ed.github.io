# frozen_string_literal: true

# REACH-01 — one Open Graph card per post, rendered from the site's own chrome.
#
# The problem this fixes, verified against the built <head>: jekyll-seo-tag gates
# its entire image block on `{% if seo_tag.image %}`, and nothing on this site
# ever set `page.image`. So every post shipped `twitter:card = summary` and no
# `og:image` at all, and a writeup pasted into a CTF Discord came out as a bare
# grey rectangle. Setting `image` is the only lever: seo-tag then emits og:image,
# og:image:width/height/alt, twitter:image, twitter:image:alt, and flips
# twitter:card to summary_large_image on its own. Nothing else here is needed to
# make that happen.
#
# What this generator does, and deliberately does not do:
#
#   * It creates a PAGE per post at /cards/<slug>/ using _layouts/card.html.
#     The card is HTML, screenshotted at 1200x630 by tools/og-cards.py after
#     `jekyll build`. Rendering the card as a real page built from the real
#     main.css and the real self-hosted Maple Mono is the whole point: an SVG
#     rasteriser or a canvas library would be a SECOND description of the design,
#     free to drift from the first. This one cannot drift, because it IS the
#     first.
#
#   * It does NOT rasterise anything. Ruby has no business shelling out to a
#     browser mid-build: `jekyll serve` would do it on every save, and a failure
#     would surface as a Jekyll backtrace rather than as a failed deploy step.
#
#   * It writes NO file into the source tree. The PNGs exist only in _site.
#
# The card page is a rendering target, not content: `sitemap: false` keeps it out
# of sitemap.xml, card.html carries `robots: noindex`, and jekyll-feed only ever
# walks site.posts, so a page cannot reach the feed at all.

module OgCards
  # The card is 1200x630 — the Open Graph 1.91:1 slot that Discord, Slack,
  # Twitter and iMessage all render large. These constants are the contract with
  # tools/og-cards.py, which screenshots at exactly this size and then asserts
  # the PNG's IHDR agrees. They are also what seo-tag emits as og:image:width and
  # og:image:height, which is what lets a scraper reserve the box before the
  # bytes arrive.
  WIDTH  = 1200
  HEIGHT = 630

  # Both halves of the same invariant, spelled once:
  #   /cards/<slug>/          the page that gets screenshotted
  #   /assets/og/<slug>.png   the file the post's og:image points at
  CARDS_DIR = "cards"
  IMAGE_DIR = "/assets/og"

  # The card page. PageWithoutAFile because there is no file — a real Page would
  # want something under the source tree to read front matter from, and there is
  # nothing to author here. That is the feature: a new post gets a card with no
  # front-matter line, no image commit, and no chance of forgetting.
  class CardPage < Jekyll::PageWithoutAFile
    def initialize(site, post, slug)
      super(site, site.source, File.join(CARDS_DIR, slug), "index.html")

      self.data = {
        "layout"  => "card",
        # Never displayed to a reader — the card page is noindex and unlinked.
        # It exists so a human opening /cards/<slug>/ in a browser to check the
        # design knows what they are looking at.
        "title"   => "og card — #{post.data["title"]}",
        # card.html looks the post back up with `where: "url"` rather than being
        # handed a Document. A Document in page data would reach Liquid as a
        # DocumentDrop only if every lookup on the path happened to cooperate;
        # a URL string is a value Liquid cannot get wrong, and it keeps the
        # layout reading `post.title`, `post.tags`, `post.content` — the same
        # names post.html uses, so the two cannot describe the post differently.
        "post_url" => post.url,
        # jekyll-sitemap filters on `doc.sitemap != false`. Without this the
        # cards would be submitted to search engines as pages, which is both
        # noise and a duplicate-title signal against the posts themselves.
        "sitemap" => false,
      }
    end
  end

  class Generator < Jekyll::Generator
    safe true

    # Default priority is deliberate: jekyll-sitemap and jekyll-feed are both
    # :lowest, so the card pages already exist (and already carry sitemap:false)
    # by the time either of them looks at site.pages.
    def generate(site)
      seen = {}

      site.posts.docs.each do |post|
        # An author who sets `image:` by hand has made a decision; overriding it
        # would be the plugin arguing with them. They get no card page either —
        # there is nothing to render and nothing to assert.
        next if post.data["image"]

        slug = slug_for(post)

        # Two posts resolving to one slug would have collided on the permalink
        # first (`/posts/:title/`), where Jekyll silently writes one over the
        # other. Here it is cheap to say so out loud, and here it would also
        # silently point two posts at one card.
        if seen.key?(slug)
          raise Jekyll::Errors::FatalException,
                "og_cards: #{post.relative_path} and #{seen[slug]} both resolve to " \
                "the slug #{slug.inspect}; their permalinks collide too. " \
                "Rename one file or give one an explicit `slug:`."
        end
        seen[slug] = post.relative_path

        # The line that fixes the actual bug. A Hash rather than a String so that
        # seo-tag's ImageDrop finds width/height/alt in its fallback data — as a
        # bare String it would emit og:image and nothing else.
        post.data["image"] = {
          "path"   => "#{IMAGE_DIR}/#{slug}.png",
          "width"  => WIDTH,
          "height" => HEIGHT,
          "alt"    => alt_for(post),
        }

        site.pages << CardPage.new(site, post, slug)
      end
    end

    private

    # The card slug must be the post's OWN url slug, not a fresh slugify of the
    # title: `:title` in the permalink resolves to data["slug"], which Jekyll
    # derives from the filename and which preserves case — this site's live,
    # indexed post URL really is /posts/Google-Capture-The-Flag-2022-madcore-pwn/.
    # Deriving the card path the same way keeps /posts/X/, /cards/X/ and
    # /assets/og/X.png the same X forever, which is what makes a missing card
    # obvious by eye. The slugify fallback only ever runs for a document with no
    # date-prefixed filename.
    def slug_for(post)
      post.data["slug"] || Jekyll::Utils.slugify(post.data["title"])
    end

    # og:image:alt is read aloud in place of the card by a screen reader, and
    # shown by some clients when the image 404s. So it describes the CARD — what
    # is drawn on it — rather than repeating og:title, which the same scraper
    # already has. Tags are joined with commas because a reader does not say the
    # spaces that separate them on the card itself.
    #
    # Curly quotes around the title, not straight ones, and the whole string goes
    # through escape_once: verified in jekyll-seo-tag 2.9.0's template.html,
    # `image.alt` is the one value interpolated into an attribute RAW —
    # `content="{{ seo_tag.image.alt }}"` with no filter, while title and
    # description are escaped inside the drop. A title with a double quote in it
    # therefore closes the attribute early and corrupts the whole <head>.
    def alt_for(post)
      bits = []
      bits << post.data["categories"].first if post.data["categories"]&.any?
      bits << post.data["tags"].join(", ")  if post.data["tags"]&.any?
      bits << post.date.strftime("%Y-%m-%d")

      escape_once("A terminal pane titled “#{post.data["title"]}” — #{bits.join(" · ")}")
    end

    HTML_ESCAPE = {
      "&" => "&amp;", "<" => "&lt;", ">" => "&gt;", '"' => "&quot;", "'" => "&#39;",
    }.freeze
    private_constant :HTML_ESCAPE

    # Liquid's own escape_once, inlined. Not CGI.escapeHTML and not
    # ERB::Util.html_escape: both would double-escape an entity the author wrote
    # deliberately, and both are a `require` of a library Ruby has been moving in
    # and out of the default gems for three releases. Five lines is cheaper than
    # either argument.
    def escape_once(str)
      str.gsub(%r{["'><]|&(?!([a-zA-Z]+|(\#\d+));)}) { |c| HTML_ESCAPE[c] }
    end
  end
end
