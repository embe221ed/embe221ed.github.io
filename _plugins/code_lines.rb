# frozen_string_literal: true

# ===========================================================================
# _plugins/code_lines.rb — wrap every logical line of every highlighted code
# block in its own <span class="cl" id="bNLM">, where N is the block's index
# in the page and M the line's index in the block, both 1-based.
#
# WHY: _config.yml turns Rouge's line numbers off, and says why — Rouge
# renders them as real digits in a <td class="gutter">, so they ride along on
# copy and a pasted exploit starts with "1 from pwn import *", which does not
# run. The replacement gutter is drawn with a CSS counter as ::before
# content, which no engine can put on the clipboard because it is not in the
# DOM at all. That needs one element per logical line — this file, and
# nothing else, is what produces them.
#
# The markup is inert: a <span> with no CSS is inline, the newline stays
# inside it, and the page renders exactly as it did before. Turning the
# gutter on is a CSS-only change, in a file owned elsewhere.
#
# `class="cl"` with the newline inside the span is Chroma's convention (the
# highlighter Hugo ships), so the CSS side has prior art to lean on: a
# trailing forced break at the end of a block box generates no extra line
# box, which is why `.cl { display: block }` does not double-space the code.
#
# WHY A DOM WALK AND NOT split("\n"): measured on
# _posts/2022-07-15-Google-Capture-The-Flag-2022-madcore-pwn.md, 15 of the
# spans Rouge emits straddle a newline — one multi-line /* */ comment, an
# #include run, and five // runs. Splitting the serialised HTML on "\n" cuts
# those spans in half and the fragments lose their class, i.e. their
# highlighting. The walker below re-clones the ancestor span chain into every
# line a token spans, so a two-line comment becomes two .cl lines each
# carrying its own <span class="cm">.
#
# The clone is node.dup(2) — libxml2's "extended = 2", which copies
# attributes and namespaces but not children. dup(0) drops the attributes,
# which silently removes class= and therefore the highlighting; dup(1) is a
# deep copy and would duplicate the text we are in the middle of moving.
#
# Everything outside <code> is left byte-identical: the block is located
# with a regex, only the inner HTML of the <code> is rebuilt, and the parse
# uses Nokogiri::HTML::DocumentFragment — the same parser jekyll-toc already
# runs over this content via the inject_anchors filter in _layouts/post.html.
# ===========================================================================

require 'nokogiri'

module Interdot
  module CodeLines
    LINE_CLASS = 'cl'

    # Kramdown + Rouge with css_class: highlight emit exactly this nesting;
    # the capture split keeps the open and close tags out of the rewrite.
    BLOCK = %r{
      (<div\s+class="highlight">\s*<pre\s+class="highlight">\s*<code[^>]*>)
      (.*?)
      (</code>\s*</pre>\s*</div>)
    }mx

    class << self
      def process(doc)
        html = doc.output
        return unless html.is_a?(String) && html.include?('<pre class="highlight">')

        index = 0
        doc.output = html.gsub(BLOCK) do
          open_tags = Regexp.last_match(1)
          inner = Regexp.last_match(2)
          close_tags = Regexp.last_match(3)
          index += 1

          rebuilt = rebuild(open_tags, inner, close_tags, index)
          rebuilt || (open_tags + inner + close_tags)
        end
      end

      private

      # Returns the rewritten block, or nil to leave the block untouched.
      def rebuild(open_tags, inner, close_tags, index)
        # Already wrapped (a second render pass), or Rouge's line_numbers
        # table is in there — in which case the lines are table rows and not
        # ours to touch.
        return nil if inner.include?(%(class="#{LINE_CLASS}")) || inner.include?('<table')

        fragment = Nokogiri::HTML::DocumentFragment.parse(open_tags + inner + close_tags)
        code = fragment.at_css('div.highlight > pre.highlight > code')
        return nil if code.nil?

        before = code.text
        lines = split_lines(code, fragment.document, index)
        return nil if lines.empty?

        code.children.to_a.each(&:unlink)
        lines.each { |line| code.add_child(line) }

        # The one invariant that matters: a copied block must still be the
        # program. If it is not, ship the block exactly as Rouge wrote it.
        return nil unless code.text == before

        open_tags + code.inner_html + close_tags
      rescue StandardError => e
        Jekyll.logger.warn 'CodeLines:', "left a code block unwrapped (#{e.class}: #{e.message})"
        nil
      end

      # Depth-first walk that regroups the token stream by line. Text nodes
      # are split after each newline; the newline stays with the line it
      # ends, so a copied .cl is a whole line including its break.
      def split_lines(code, document, index)
        lines = []
        line = nil
        open = []   # [[source element, clone or nil], …] — the current chain

        start_line = lambda do
          line = Nokogiri::XML::Node.new('span', document)
          line['class'] = LINE_CLASS
          line['id'] = format('b%dL%d', index, lines.length + 1)
          open = open.map { |source, _| [source, nil] }
        end

        # Clones are materialised only when something is actually appended
        # inside them, so a token that ends exactly on a newline does not
        # leave an empty span at the head of the next line.
        cursor = lambda do
          parent = line
          open.each_with_index do |(source, clone), depth|
            if clone.nil?
              clone = source.dup(2)
              parent.add_child(clone)
              open[depth] = [source, clone]
            end
            parent = clone
          end
          parent
        end

        visit = lambda do |node|
          case node
          when Nokogiri::XML::Text
            node.content.split(/(?<=\n)/).each do |fragment|
              cursor.call.add_child(Nokogiri::XML::Text.new(fragment, document))
              next unless fragment.end_with?("\n")

              lines << line
              start_line.call
            end
          when Nokogiri::XML::Element
            open.push([node, nil])
            node.children.to_a.each { |child| visit.call(child) }
            open.pop
          else
            cursor.call.add_child(node.dup(1))
          end
        end

        start_line.call
        code.children.to_a.each { |child| visit.call(child) }
        # Rouge always ends a block with a newline, so the pending line is
        # normally empty; a block that does not gets its last line here.
        lines << line if line.children.any?

        lines
      end
    end
  end
end

Jekyll::Hooks.register %i[posts pages], :post_render do |doc|
  # atom.xml and feed.xml are pages too, and neither is HTML.
  Interdot::CodeLines.process(doc) if doc.output_ext == '.html'
end
