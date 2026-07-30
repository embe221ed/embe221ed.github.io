# frozen_string_literal: true

# ===========================================================================
# _plugins/link_check.rb — fail the build on a link that goes nowhere.
#
# Two failure modes, both of which shipped silently before this existed and
# neither of which is visible without clicking:
#
#   1. AN INTERNAL LINK TO A PAGE THAT WAS NEVER GENERATED. jekyll-archives
#      builds its term pages at Utils.slugify(title), so a tag written
#      `Heap Grooming` lives at /tags/heap-grooming/. Three templates linked
#      the term verbatim instead, which is correct for every lowercase
#      single-word tag and dead for the first one that is not.
#
#   2. A DUPLICATE id, WHICH SILENTLY REDIRECTS EVERY FRAGMENT TO IT. The
#      madcore post has a `#### main()` heading; jekyll-toc slugs that to
#      id="main", which collided with the <main id="main"> landmark. Every
#      href="#main" on the page — the heading's own anchor and its contents
#      entry included — resolved to whichever element came first, so the
#      table of contents jumped to the top of the article instead of the
#      section.
#
# Both are the same shape of bug: correct for the content that existed when
# the template was written, wrong for content added later. That is exactly
# what a build-time check is for, and it is why this runs on every build
# rather than living in a script someone has to remember.
#
# WHAT IT CHECKS
#   * every root-relative href/src resolves to a file or a directory index
#   * every #fragment resolves to an id on the page it points at, including
#     cross-page fragments like /posts/x/#section
#   * no id appears twice on one page
#
# WHAT IT DOES NOT CHECK, deliberately, to stay free of false positives:
#   * absolute URLs, including this site's own — canonical tags and og:url
#     are emitted by seo-tag against site.url and are not navigation
#   * relative hrefs that are not root-relative; nothing here emits them,
#     and resolving them correctly means tracking each page's own directory
#   * mailto:, data:, tel:, and protocol-relative //host/path
#
# Set CHECK_LINKS=0 to downgrade every finding to a warning. That exists for
# the case where this check is itself wrong — not as a way to ship a dead
# link, which is why it is off by default and prints what it skipped.
# ===========================================================================

require "set"

module LinkCheck
  # href/src only. `content=` carries absolute og: URLs and `srcset` carries
  # descriptors, and neither is a link a reader can follow.
  ATTR = /(?:href|src)\s*=\s*"([^"]*)"/.freeze
  ID   = /\sid\s*=\s*"([^"]+)"/.freeze

  SKIP = %r{\A(?:[a-z][a-z0-9+.-]*:|//)}i.freeze

  class << self
    def run(site)
      dest = site.dest
      pages = Dir.glob(File.join(dest, "**", "*.html"))
      return if pages.empty?

      ids  = {}   # page path -> Set of ids
      dups = []
      pages.each do |path|
        html = File.read(path, encoding: "utf-8")
        seen = Set.new
        repeated = Set.new
        html.scan(ID) { |(id)| repeated << id unless seen.add?(id) }
        ids[path] = seen
        repeated.each { |id| dups << [rel(dest, path), id] }
      end

      dead = []
      pages.each do |path|
        html = File.read(path, encoding: "utf-8")
        html.scan(ATTR).flatten.uniq.each do |raw|
          url = raw.strip
          next if url.empty? || url == "#" || url =~ SKIP

          target, _, frag = url.partition("#")
          frag = decode(frag)

          if target.empty?
            # same-page fragment
            unless ids[path].include?(frag)
              dead << [rel(dest, path), url, "no element with id #{frag.inspect} on this page"]
            end
            next
          end

          # Only root-relative paths are resolvable without tracking the
          # emitting page's directory. Nothing here emits anything else.
          next unless target.start_with?("/")

          file = resolve(dest, decode(target))
          if file.nil?
            dead << [rel(dest, path), url, "no file generated at #{target}"]
          elsif !frag.empty? && file.end_with?(".html") && !ids.fetch(file, Set.new).include?(frag)
            dead << [rel(dest, path), url, "#{rel(dest, file)} has no id #{frag.inspect}"]
          end
        end
      end

      report(dups, dead)
    end

    private

    def decode(s)
      s.gsub(/%([0-9A-Fa-f]{2})/) { [Regexp.last_match(1)].pack("H2") }
    end

    # Returns the file a URL path resolves to, or nil. Mirrors how a static
    # host serves a directory: /foo/ and /foo both find /foo/index.html.
    def resolve(dest, path)
      base = File.join(dest, path.sub(%r{\A/}, ""))
      idx  = File.join(base, "index.html")
      return idx  if File.file?(idx)
      return base if File.file?(base)

      nil
    end

    def rel(dest, path)
      path.sub(%r{\A#{Regexp.escape(dest)}/?}, "")
    end

    def report(dups, dead)
      return if dups.empty? && dead.empty?

      lines = []
      unless dups.empty?
        lines << "  duplicate ids (every fragment pointing at one silently wins the first):"
        dups.sort.each { |page, id| lines << "    #{page}: id=#{id.inspect} appears more than once" }
      end
      unless dead.empty?
        lines << "  links that go nowhere:" unless dead.empty?
        dead.sort.each { |page, url, why| lines << "    #{page}: #{url} — #{why}" }
      end

      msg = "link_check found #{dups.size + dead.size} problem(s):\n" + lines.join("\n")

      if ENV["CHECK_LINKS"] == "0"
        Jekyll.logger.warn "link_check:", "#{msg}\n  (CHECK_LINKS=0, not failing the build)"
      else
        raise Jekyll::Errors::FatalException,
              "#{msg}\n  Set CHECK_LINKS=0 to downgrade this to a warning."
      end
    end
  end
end

Jekyll::Hooks.register :site, :post_write do |site|
  LinkCheck.run(site)
end
