# frozen_string_literal: true

# ===========================================================================
# _plugins/hexdump_lexer.rb — a Rouge lexer for hex dumps.
#
# Registered as ```hexdump (aliases: xxd, hexyl). Reads what `xxd`, `xxd -g1`
# and `hexdump -C` actually print, including the `*` repeat marker, short
# final lines, offset-only lines, and a hand-drawn annotation trailing the
# ASCII pane — the madcore writeup has all of those, fenced as ```python
# today because Rouge 4.7.0 has no hexdump lexer at all
# (Rouge::Lexer.find('hexdump') → nil, checked against Gemfile.lock).
#
# This is not a regex lexer: the ASCII pane cannot be coloured from its own
# characters. `xxd` prints `.` for every unprintable byte, so a `.` in the
# pane is ambiguous unless you read the byte it stands for out of the hex
# column. The lexer therefore parses each line as offset / hex column /
# pane, categorises the bytes once, and colours BOTH columns from the same
# decision — which is what the approved PWN-01 specimen shows.
#
# TOKEN CONTRACT (assets/css/syntax.css is owned elsewhere — these are the
# classes it has to target, with the role each one resolves to today):
#
#   offset column, `00000d60:` and `*`   Generic::Prompt        .gp  muted, unselectable
#   null byte, 00                        Generic::Output        .go  muted
#   printable ASCII, 21..7e              Literal::String        .s   accent
#   whitespace byte, 09-0d and 20        Text::Whitespace       .w   fg
#   non-ASCII and C0 control             Literal::Number::Hex   .mh  special
#   `|` guards of a `hexdump -C` pane    Punctuation            .p   muted
#   anything that is not a dump line     Text                   —    fg
#
# The ASCII pane carries the same four byte-category tokens as the hex
# column, per the specimen — Rouge emits a flat token stream, so there is no
# way to wrap the pane in a container and no need to: a pane character and
# the byte it renders are the same fact.
#
# The specimen's hues are success / info / accent2 for printable /
# whitespace / non-ASCII. Three language-scoped rules land them exactly, the
# same pattern syntax.css already uses for `.language-diff .highlight .p`:
#
#   div.language-hexdump .highlight .s  { color: var(--id-success, #626d2a); }
#   div.language-hexdump .highlight .w  { color: var(--id-info,    #436d77); }
#   div.language-hexdump .highlight .mh { color: var(--id-accent2, #a65009); }
#
# Failure mode, deliberately chosen: a line this lexer cannot parse is
# emitted as one Text token, and any exception inside a line falls back to
# the same. A malformed dump degrades to plain text; it never fails a build.
# ===========================================================================

require 'rouge'

module Rouge
  module Lexers
    class Hexdump < Rouge::Lexer
      title 'hexdump'
      desc 'xxd / hexdump -C output, coloured by byte category'
      tag 'hexdump'
      aliases 'xxd', 'hexyl'

      # `xxd` writes `.` for every byte it cannot print, which flattens three
      # different things into one glyph. Substituting the placeholder — and
      # only the placeholder, never a real 0x2e — gives the pane a second,
      # non-colour channel, which is the reason the PWN-01 specimen shows
      # `0` / `_` / `·` there. All three are in the shipped Maple Mono.
      # Set to false to render the pane exactly as the tool printed it.
      #
      # FALSE, and it has to be. The madcore post hands the reader a procedure —
      # "`:%!xxd` inside nvim to edit it in a more human-friendly format" — and
      # then shows the dump they are meant to be looking at. nvim prints `.`.
      # Substituting `0`/`_`/`·` would make the page disagree with the tool it
      # just told them to run, which is a worse failure than the missing channel
      # the substitution was buying. Colour already distinguishes the four byte
      # categories in both the hex column and the pane.
      PANE_GLYPHS = false
      PLACEHOLDER = '.'
      GLYPH = { null: '0', space: '_', other: '·' }.freeze

      TOKEN = {
        null:  Generic::Output,
        print: Str,
        space: Text::Whitespace,
        other: Num::Hex
      }.freeze

      # An offset, then either xxd's `:` or hexdump's two spaces.
      OFFSET = /\A([ \t]*)(\h{4,16})(:?)([ \t]*)(.*)\z/m

      def stream_tokens(str, &out)
        str.each_line { |line| lex_line(line, out) }
      end

      private

      # Tokens for a line are buffered and only flushed once the whole line
      # has parsed. Emitting as we go would leave half a line of spans behind
      # if anything went wrong, and the fallback would then duplicate it.
      def lex_line(line, out)
        body = line.chomp("\n")
        newline = line[body.length..-1].to_s
        buffer = []

        emit_body(body, ->(tok, val) { buffer << [tok, val] })
        buffer << [Text, newline] unless newline.empty?
        buffer.each { |tok, val| out.call(tok, val) }
      rescue StandardError
        # A dump is data, not source: no shape of it is worth a failed build.
        out.call(Text, line.dup)
      end

      def emit_body(body, out)
        # `*` is how both xxd and hexdump say "the previous line, repeated".
        # It stands in the offset column, so it takes the offset token.
        if body =~ /\A([ \t]*)(\*)([ \t]*)\z/
          out.call(Text, $1)
          out.call(Generic::Prompt, $2)
          out.call(Text, $3)
          return
        end

        m = OFFSET.match(body)
        return out.call(Text, body) unless m

        indent, offset, colon, gap, rest = m.captures

        # The final line of `hexdump -C` is the end offset and nothing else.
        if colon.empty? && gap.strip.empty? && rest.empty? && offset.length >= 8
          out.call(Text, indent) unless indent.empty?
          out.call(Generic::Prompt, offset)
          out.call(Text, gap) unless gap.empty?
          return
        end

        # A bare hex run with no separator after it is prose, not a dump line
        # (`0x2000000000000020` in a sentence, say). Require xxd's colon or
        # hexdump's whitespace gap.
        return out.call(Text, body) if colon.empty? && gap.empty?

        hex, pane, guards, tail = split_columns(rest)
        return out.call(Text, body) if hex.nil?

        out.call(Text, indent) unless indent.empty?
        out.call(Generic::Prompt, offset + colon)
        out.call(Text, gap) unless gap.empty?

        bytes = emit_hex(hex, out)
        emit_pane(pane, guards, bytes, out)
        out.call(Text, tail) unless tail.nil? || tail.empty?
      end

      # Returns [hex_column, pane, guards, tail]; pane and guards may be nil.
      #
      # hexdump -C brackets its pane in `|`, which is unambiguous. xxd does
      # not, so the split is decided by arithmetic over every run of two or
      # more spaces: the left side must be nothing but hex byte pairs, and
      # the right side must be at least as long as the byte count. A gap
      # where the two match EXACTLY wins, because `hexdump -C` and
      # `xxd -c 16 -g 8` both put a wide gap in the middle of the byte
      # column, which is otherwise a plausible-looking split. When nothing
      # matches exactly the widest byte column wins, which is what keeps the
      # annotated dumps in the post — where a hand-drawn ruler follows the
      # pane — from being cut in the middle.
      def split_columns(rest)
        if (m = /\A([\h ]*?)(\|)([^|\n]*)(\|)([ \t]*)\z/.match(rest))
          return [m[1], m[3], [m[2], m[4]], m[5]]
        end

        best = nil
        offset = 0

        while (gap = /[ \t]{2,}/.match(rest, offset))
          left = rest[0...gap.begin(0)]
          right = rest[gap.end(0)..-1].to_s
          count = byte_count(left)
          offset = gap.end(0)

          next unless count.positive? && hex_only?(left) && right.length >= count

          exact = right.length == count
          best = [left + gap[0], right[0, count], nil, right[count..-1], exact, count] \
            if best.nil? || (exact && !best[4]) || (exact == best[4] && count > best[5])

          break if exact
        end

        return best[0, 4] if best

        # No pane: either the whole line is hex (hexdump -x, or xxd piped
        # through `cut`), or it is not a dump line at all.
        hex_only?(rest.rstrip) && byte_count(rest).positive? ? [rest, nil, nil, nil] : nil
      end

      def hex_only?(str)
        str.match?(/\A[\h \t]*\z/)
      end

      def byte_count(str)
        str.count('0-9a-fA-F') / 2
      end

      # Emits the hex column and returns the byte values, in order, so the
      # pane can be coloured from the same decision. Each byte carries the
      # whitespace that follows it, so a run of one category collapses into a
      # single span — `0000 0000 0000 0000 ` rather than eight of them.
      def emit_hex(hex, out)
        bytes = []
        pos = 0

        while pos < hex.length
          if (m = /\A(\h\h)([ \t]*)/.match(hex[pos..-1]))
            value = m[1].to_i(16)
            bytes << value
            out.call(TOKEN[category(value)], m[0])
            pos += m[0].length
          elsif (m = /\A[ \t]+/.match(hex[pos..-1]))
            out.call(Text, m[0])
            pos += m[0].length
          else
            # An odd trailing nibble, or a character that is not hex at all.
            out.call(Text, hex[pos])
            pos += 1
          end
        end

        bytes
      end

      def emit_pane(pane, guards, bytes, out)
        return if pane.nil?

        out.call(Punctuation, guards[0]) if guards

        pane.each_char.with_index do |char, i|
          value = bytes[i]
          if value.nil?
            out.call(Text, char)
            next
          end

          cat = category(value)
          # +"" on the substitute: Rouge's own token consolidator appends to
          # the previously yielded value in place, so a frozen string literal
          # (this file is frozen_string_literal) would raise there.
          char = +GLYPH[cat] if PANE_GLYPHS && char == PLACEHOLDER && value != 0x2e
          out.call(TOKEN[cat], char)
        end

        out.call(Punctuation, guards[1]) if guards
      end

      # hexyl's categories, minus its split between control and non-ASCII:
      # both are bytes you cannot read as text, and the post's dumps contain
      # far more of them than of anything else.
      def category(value)
        case value
        when 0x00 then :null
        when 0x09..0x0d, 0x20 then :space
        when 0x21..0x7e then :print
        else :other
        end
      end
    end
  end
end
