# frozen_string_literal: true

# ===========================================================================
# _plugins/telescope_lexer.rb — a Rouge lexer for pwndbg context output.
#
# Registered as ```telescope (aliases: pwndbg, gef). Covers what a heap or
# stack writeup actually pastes: the `[ REGISTERS ]` / `[ STACK ]` banners,
# register rows, the `00:0000│` index gutter, `telescope`'s pointer chains,
# the string at the end of a chain, `info registers`, and the `x/10xg` rows
# the madcore post is full of.
#
# WHY: Rouge 4.7.0 has no gdb lexer of any kind (Rouge::Lexer.find('gdb') →
# nil), so a telescope block today is either plain text or mislabelled as
# ```python — which is what the madcore post does with its `x/10xg` dumps.
#
# TOKEN CONTRACT (assets/css/syntax.css is owned elsewhere — these are the
# classes it has to target, with the role each one resolves to today):
#
#   `00:0000│` index gutter              Generic::Prompt        .gp  muted, unselectable
#   `pwndbg>` prompt                     Generic::Prompt        .gp  muted, unselectable
#   banner rule, `─────`                 Punctuation            .p   muted
#   banner label, `[ REGISTERS ]`        Generic::Subheading    .gu  info bold
#   register name, `RSI` / `rax`         Name::Variable         .nv  info
#   frame marker, `rsp` / `rbp` in a row Generic::Strong        .gs  fg-strong bold
#   pwndbg's `*` changed-value marker    Generic::Strong        .gs  fg-strong bold
#   pointer-chain arrow, `─➜` / `◂—`     Punctuation            .p   muted
#   hex value, `0x5647a04a5730`          Literal::Number::Hex   .mh  special
#   decimal value (info registers)       Literal::Number::Integer .mi special
#   string at the end of a chain         Literal::String        .s   accent
#   symbol, `(ParseNtFile+0x11a)`        Name::Function         .nf  success
#   `x/10xg` row address                 Name::Label            .nl  info
#   flag set, `[ CF SF IF RF ]`          Name::Constant         .no  accent2
#   `# …` and pwndbg's `/* '8' */`       Comment::Single/Multiline .c1/.cm muted italic
#   everything else                      Text                   —    fg
#
# The approved PWN-03 specimen dims the banner rules and prints the hex
# values in body colour. Two language-scoped rules land that, the same
# pattern syntax.css already uses for `.language-diff .highlight .p`:
#
#   div.language-telescope .highlight .gu { color: var(--id-accent2, #a65009); }
#   div.language-telescope .highlight .mh { color: var(--id-fg, #654735); }
#
# Nothing here can raise: :root is only ever entered at a line start, every
# state pops on \n, and each state ends in a catch-all.
# ===========================================================================

require 'rouge'

module Rouge
  module Lexers
    class Telescope < RegexLexer
      title 'telescope'
      desc 'pwndbg / gef context output — registers, stack, pointer chains'
      tag 'telescope'
      aliases 'pwndbg', 'gef'

      REGISTER = %r/
        (?:
            r(?:[abcd]x|[sd]i|[sb]p|ip|[8-9]|1[0-5])[dwb]?
          | e(?:[abcd]x|[sd]i|[sb]p|ip|flags)
          | [abcd]x | [abcd][lh] | [cdefgs]s
          | [xyz]mm(?:3[01]|[12]\d|\d) | st\d | k[0-7]
          | fs_base | gs_base | orig_rax
        )
        (?!\w)
      /xi

      # pwndbg draws its chains with an em dash and U+25B8 (`—▸`), and ends
      # them with U+25C2 (`◂—`). Neither Geometric Shapes arrow is confirmed
      # present in the shipped Maple Mono subset, and a missing glyph renders
      # as tofu, so both are swapped for glyphs that ARE in it — U+279C and
      # U+276E — which is the same substitution the approved PWN-03 specimen
      # made (`─➜`). Only the arrowhead changes; the rule glyph next to it is
      # already U+2500/U+2014 and is left alone.
      GLYPH_SUBSTITUTIONS = { "\u25B8" => "\u279C", "\u25C2" => "\u276E" }.freeze

      ARROW = %r/(?:[-—─=]+[>▸➜]|[<◂❮]+[-—─=]+|->|<-|→|←|▸|◂)/

      state :root do
        rule %r/\n/, Text

        # `─────────[ REGISTERS ]──────────`, and gef's `[ registers ]` with
        # ASCII rules. The label is the only heading pwndbg prints.
        rule %r/([─—=*-]{2,})(\[)([^\[\]\n]*)(\])([─—=*-]*)/ do
          groups Punctuation, Punctuation, Generic::Subheading,
                 Punctuation, Punctuation
        end

        rule %r/^(?:pwndbg|gef|gdb)>|^\(gdb\)/, Generic::Prompt, :command

        # The stack index gutter: `00:0000│`. Unselectable by way of .gp, so
        # copying a telescope block yields addresses and values only — the
        # same clipboard reasoning syntax.css already documents for prompts.
        rule %r/^[ \t]*\h\h:\h{4}[│|]/, Generic::Prompt, :line

        # A register row: `*RAX  0x0`, ` RSI  0x5647a04a5730 ─➜ …`, and
        # `info registers`' lowercase `rax            0x57e    1406`.
        rule %r/^([ \t]*)([*►▶]?)([ \t]*)(#{REGISTER})(?=[ \t:])/ do
          groups Text, Generic::Strong, Text, Name::Variable
          push :line
        end

        # `x/10xg 0x562592378df0` rows: an address, then the words at it.
        rule %r/^([ \t]*)(0x\h+)(:)/ do
          groups Text, Name::Label, Punctuation
          push :line
        end

        # `vmmap` rows: two addresses, then permissions and the mapping name.
        # The madcore post pastes one to prove where R14 pointed.
        rule %r/^[ \t]+(?=0x\h+[ \t]+0x\h+[ \t])/ do
          token Text
          push :line
        end

        # Prose between blocks, a whole line at a time so that none of the
        # unanchored rules above can match in the middle of a sentence.
        rule %r/[^\n]+/, Text
      end

      state :line do
        rule %r/\n/, Text, :pop!
        rule %r/[ \t]+/, Text

        rule %r/#[^\n]*/, Comment::Single
        rule %r{/\*.*?\*/}, Comment::Multiline

        rule ARROW do
          token Punctuation, substitute_glyphs(@current_stream[0])
        end

        rule %r/'(?:\\.|[^'\\\n])*'/, Str
        rule %r/"(?:\\.|[^"\\\n])*"/, Str

        # `(Corefile::ParseNtFile+0x11a)` and `<main+0x8c>` — where a pointer
        # actually lands, which is the whole point of a telescope block.
        rule %r/([(<])([A-Za-z_.][\w:.@$]*)([+-])(0x\h+|\d+)([)>])/ do
          groups Punctuation, Name::Function, Operator, Num::Hex, Punctuation
        end
        rule %r/([(<])([A-Za-z_.][\w:.@$]*)([)>])/ do
          groups Punctuation, Name::Function, Punctuation
        end

        # `eflags 0x10283 [ CF SF IF RF ]`, and vmmap's `[stack]` / `[heap]`.
        rule %r/\[[ \t]*(?:[A-Z]{2}[ \t]*)+\]/, Name::Constant
        rule %r/\[(?:stack|heap|vvar|vdso|vsyscall|anon[\w.]*)\]/, Name::Constant

        rule %r/-?0x\h+/, Num::Hex
        rule %r/\b\d+\b/, Num::Integer

        # pwndbg names the frame registers in lower case in the gutter rows
        # (`00:0000│ rsp`) and in upper case in the REGISTERS section, so the
        # case is enough to tell a marker from a value.
        rule %r/\b(?:rsp|rbp|rip|rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r1[0-5])\b/,
             Generic::Strong
        rule %r/#{REGISTER}/, Name::Variable

        rule %r/[│|]/, Punctuation
        rule %r/[^\n]/, Text
      end

      state :command do
        rule %r/\n/, Text, :pop!
        rule %r/\$\w+/, Name::Variable
        rule %r/0x\h+/, Num::Hex
        rule %r/[^\n]/, Text
      end

      private

      # Returns a new String either way: Rouge's token consolidator appends
      # to the previously yielded value in place, and this file is
      # frozen_string_literal.
      def substitute_glyphs(value)
        value.gsub(/[\u25B8\u25C2]/) { |c| GLYPH_SUBSTITUTIONS[c] }
      end
    end
  end
end
