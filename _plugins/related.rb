# frozen_string_literal: true

# ===========================================================================
# _plugins/related.rb — related posts, ranked by shared tags.
#
# Jekyll ships `site.related_posts`, but without the `--lsi` flag it is just
# "the most recent posts that are not this one" — it does not look at the post
# at all. Turning LSI on pulls in a matrix library and makes the build slow
# enough to notice, to answer a question that shared tags already answer well.
#
# So: rank by how many tags two posts have in common, break ties on the
# category matching, then on recency. A post with nothing in common never
# appears — an empty list is a true statement, and padding it with recent posts
# is what made the built-in one useless.
#
# Runs once over all posts at build rather than per-page in Liquid, which is
# what keeps this O(posts²) loop off the rendering path. With a few hundred
# posts it is still milliseconds; if it ever is not, the fix is an inverted
# index by tag, not a rewrite.
#
# Sets `post.data["related"]` to an array of Documents, so the template does
# `for r in page.related` and reads `r.url`, `r.title`, `r.date` normally.
# ===========================================================================

module Related
  MAX = 3

  class Generator < Jekyll::Generator
    safe true
    priority :low

    def generate(site)
      posts = site.posts.docs
      # Sets, not arrays: the intersection below is the whole job, and it is
      # done once per pair. Downcased so `Heap Grooming` and `heap grooming`
      # are one tag here for the same reason they are one page in the archive.
      tags = posts.to_h { |p| [p, norm(p.data["tags"]).to_set] }
      cats = posts.to_h { |p| [p, norm(p.data["categories"]).first] }

      posts.each do |post|
        mine = tags[post]
        next post.data["related"] = [] if mine.empty?

        scored = posts.filter_map do |other|
          next if other.equal?(post)

          shared = (mine & tags[other]).size
          next if shared.zero?

          [shared, cats[other] == cats[post] ? 1 : 0, other.date.to_i, other]
        end

        # Descending on every key: most shared tags, then same category, then
        # newest. sort_by is ascending, so the numeric keys are negated rather
        # than the array reversed — reversing would also flip the tie order.
        post.data["related"] =
          scored.sort_by { |s, c, d, _| [-s, -c, -d] }.first(MAX).map(&:last)
      end
    end

    private

    # Front matter tags may be a string ("pwn binexp"), a list, or absent.
    # Jekyll normalises for its own use; this does the same for ours.
    def norm(value)
      case value
      when nil    then []
      when String then value.split
      when Array  then value
      else Array(value)
      end.map { |v| v.to_s.downcase.strip }.reject(&:empty?)
    end
  end
end
