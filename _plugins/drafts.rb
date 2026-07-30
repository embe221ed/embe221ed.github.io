# frozen_string_literal: true

# ===========================================================================
# _plugins/drafts.rb — `_drafts/*.md` becomes the drafts listing.
#
# Jekyll already has a place for an unfinished post: _drafts/. It just does
# not build them without --drafts, so the homepage had no way to see them and
# a draft had to be announced by hand in _data/drafts.yml — a second copy of
# the date, category and title of a file that already stated all three.
# Two places to edit, and they drift.
#
# This reads the front matter of every file in _drafts/ and turns it into the
# same rows the listing already renders. Writing a draft is now: put a file in
# _drafts/. Publishing it is: move it to _posts/ with a dated filename. No
# data file, no third step.
#
# _data/drafts.yml STILL WORKS and its rows are merged in. It is the right
# tool for a draft whose text you do not want in a public repo — a row there
# advertises the title without committing the prose. Rows from both sources
# are sorted together, newest first.
#
# The draft's BODY is never read and never rendered. This only ever emits the
# three fields the listing shows.
#
#   date      front matter `date:`, else a YYYY-MM-DD- filename prefix, else
#             nothing. A draft with no date renders without one rather than
#             being given a fake — mtime would have been today's date on
#             every CI checkout, which is worse than an empty column.
#   category  `category:`, or the first of `categories:`
#   title     `title:`, else the filename with dashes turned back into spaces
# ===========================================================================

require "yaml"

module Drafts
  FRONT_MATTER = /\A---\s*\n(.*?\n?)^---\s*$\n?/m.freeze
  DATED_NAME   = /\A(\d{4}-\d{2}-\d{2})-(.*)\z/.freeze

  class << self
    def rows_from_disk(site)
      dir = File.join(site.source, "_drafts")
      return [] unless Dir.exist?(dir)

      Dir.glob(File.join(dir, "*.{md,markdown}")).sort.filter_map do |path|
        row_for(path)
      end
    end

    private

    def row_for(path)
      text = File.read(path, encoding: "utf-8")
      match = text.match(FRONT_MATTER)
      data = {}
      if match
        begin
          data = YAML.safe_load(match[1], permitted_classes: [Date, Time], aliases: true) || {}
        rescue StandardError => e
          # A draft is by definition half-finished; broken YAML in one must not
          # take the whole site down. It is announced and skipped.
          Jekyll.logger.warn "drafts:", "skipping #{File.basename(path)} — #{e.message}"
          return nil
        end
      end
      data = {} unless data.is_a?(Hash)

      base = File.basename(path).sub(/\.(md|markdown)\z/, "")
      name_date, stem = (m = base.match(DATED_NAME)) ? [m[1], m[2]] : [nil, base]

      date = data["date"] || name_date
      date = date.strftime("%Y-%m-%d") if date.respond_to?(:strftime)

      {
        "date"     => date&.to_s,
        "category" => data["category"] || Array(data["categories"]).first,
        "title"    => data["title"] || stem.tr("-_", " "),
      }
    end
  end
end

# post_read: _data is loaded by then, so hand-written rows are already in
# site.data and this merges into them rather than racing them.
Jekyll::Hooks.register :site, :post_read do |site|
  declared = site.data["drafts"]
  declared = [] unless declared.is_a?(Array)
  declared = declared.select { |r| r.is_a?(Hash) }

  rows = declared + Drafts.rows_from_disk(site)

  # Newest first, matching site.posts. Undated rows sort last rather than
  # crashing the comparison or claiming to be the oldest thing here.
  rows = rows.sort_by { |r| [r["date"].nil? ? 1 : 0, r["date"].nil? ? "" : r["date"].to_s] }
             .partition { |r| r["date"] }
  dated, undated = rows
  site.data["drafts"] = dated.sort_by { |r| r["date"].to_s }.reverse + undated
end
