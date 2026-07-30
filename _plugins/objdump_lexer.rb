# frozen_string_literal: true

# ===========================================================================
# _plugins/objdump_lexer.rb — a Rouge lexer for disassembly.
#
# Registered as ```objdump (aliases: gas, asm, disas, gdb). Handles real
# `objdump -d` output and the gdb/pwndbg shapes that appear next to it in a
# writeup: `disassemble`, `x/10i $pc`, and the `=>` current-instruction
# marker.
#
# WHY this file exists: Rouge 4.7.0 (Gemfile.lock) ships 228 lexers and not
# one of them lexes disassembly — `Rouge::Lexer.find` returns nil for
# objdump, gas, asm and gdb; only nasm and armasm exist, and neither
# understands an address column or an opcode byte column. That absence is
# the mechanical reason the madcore writeup fences its disassembly as ```cpp
# or as plain text. This removes it.
#
# TOKEN CONTRACT (assets/css/syntax.css is owned elsewhere — these are the
# classes it has to target, with the role each one already resolves to):
#
#   instruction address, `1f8a:`          Name::Label            .nl  info
#   opcode byte column, `e8 51 f1 ff ff`  Generic::Output        .go  muted
#   mnemonic, `call` / `mov`              Keyword                .k   danger
#   prefix, `rep` / `lock`                Keyword::Reserved      .kr  danger
#   register, `%rbp` / `rdi` / `ymm0`     Name::Variable         .nv  info
#   immediate / displacement, `$0x0`      Literal::Number::Hex   .mh  special
#   `<+12>` gdb frame offset              Literal::Number::Integer .mi special
#   branch target symbol, `<read@plt>`    Name::Function         .nf  success
#   operand size, `QWORD PTR`             Keyword::Type          .kt  accent
#   `# comment` tail                      Comment::Single        .c1  muted
#   `madcore: file format …`              Generic::Heading       .gh  fg-strong
#   `Disassembly of section .text:`       Generic::Subheading    .gu  info bold
#   gdb `=>` current-instruction marker   Generic::Strong        .gs  fg-strong
#   `pwndbg>` / `(gdb)` prompt            Generic::Prompt        .gp  muted, unselectable
#   `...` (objdump's elision marker)      Comment                .c   muted
#   everything else                       Text                   —    body fg
#
# The approved PWN-06 specimen renders the address and the byte column
# muted; .nl is info today, so matching the specimen exactly needs one
# language-scoped rule (`div.language-objdump .highlight .nl`), the same
# pattern syntax.css already uses for `.language-diff .highlight .p`.
#
# Two known constraints, both accepted:
#   * objdump lays its columns out with hard tabs at tab-8; syntax.css sets
#     tab-size: 4 on div.highlight, so a pasted-with-tabs dump needs
#     `div.language-objdump { tab-size: 8 }` to line up. Tabs are emitted
#     verbatim (as Text) rather than expanded, so copy still yields the
#     bytes objdump printed.
#   * Nothing here can raise: every state ends in a catch-all, and an
#     unmatched byte degrades to one Error token, never a build failure.
# ===========================================================================

require 'rouge'

module Rouge
  module Lexers
    class Objdump < RegexLexer
      title 'objdump'
      desc 'objdump -d and gdb/pwndbg disassembly output'
      tag 'objdump'
      aliases 'gas', 'asm', 'disas', 'gdb'

      # AT&T operands carry a % sigil, so they need no list. Intel syntax
      # (`objdump -M intel`, and everything pwndbg prints) does not, and a
      # bare `rax` is otherwise indistinguishable from a symbol name — hence
      # the explicit set. Covers the x86-64 GPRs and their 32/16/8-bit
      # aliases, the segment and flag registers, and the vector files, which
      # is what `x/10i $pc` printed in the madcore post (`vpcmpeqb ymm1,
      # ymm0,YMMWORD PTR [rdi]`).
      REGISTER = %r/
        (?:
            r(?:[abcd]x|[sd]i|[sb]p|ip|[8-9]|1[0-5])[dwb]?
          | e(?:[abcd]x|[sd]i|[sb]p|ip|flags)
          | [abcd]x | [abcd][lh] | [sd]il? | [sb]pl?
          | [xyz]mm(?:3[01]|[12]\d|\d)
          | st\(\d\) | mm[0-7] | k[0-7]
          | [cdefgs]s | [cd]r\d+ | tr\d | fs_base | gs_base
        )
        (?!\w)
      /xi

      # Intel-syntax memory operands: `QWORD PTR [rip+0x2e9f]`. The size
      # word is a type, not a mnemonic, so it must not take the keyword
      # colour the mnemonic uses.
      PTR_SIZE = %r/(?:byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte|fword)\s+ptr\b/i

      state :root do
        rule %r/\n/, Text

        # `madcore:     file format elf64-x86-64` — objdump's first line.
        rule %r/^\S+:[ \t]+file format[ \t]+\S+[ \t]*$/, Generic::Heading

        # `Disassembly of section .text:`
        rule %r/^Disassembly of section .*:[ \t]*$/, Generic::Subheading

        # objdump's elision marker for a run of identical bytes.
        rule %r/^[ \t]*\.\.\.[ \t]*$/, Comment

        # A debugger prompt line. pwndbg is what the madcore post used, so
        # its prompt is first; the shell `$`/`#` forms are deliberately not
        # here — a bare `$` is an AT&T immediate.
        rule %r/^(?:pwndbg|gef|gdb)(?:>|\u276f)|^\(gdb\)/, Generic::Prompt, :command

        rule %r/[ \t]+/, Text

        # gdb marks the current instruction with `=>`, pwndbg's DISASM pane
        # with U+25BA, both before the address — so the address rules below
        # must be reachable mid-line rather than anchored to ^, hence no
        # anchors from here on. That is safe because :root is only ever
        # entered at a line start: every state pops on \n, and the last rule
        # in this state swallows a whole unrecognised line.
        rule %r/=>|[►▶]/, Generic::Strong

        # gdb frame form: `   0x0000555555555181 <+8>:\tmov …`. Ahead of the
        # symbol forms below, whose `[^<>\n]+` would otherwise swallow `+8`
        # as a symbol name.
        rule %r/((?:0x)?\h+)([ \t]+)(<)(\+)(\d+)(>)(:?)/ do
          groups Name::Label, Text, Punctuation, Operator,
                 Num::Integer, Punctuation, Punctuation
          push :instruction
        end

        # Function header: `0000000000001f26 <main>:`, and pwndbg's
        # `0x401136 <main+4>    lea …`, which continues past the symbol.
        rule %r/((?:0x)?\h+)([ \t]+)(<)([^<>+\n]+)([+-])(0x\h+|\d+)(>)(:?)/ do
          groups Name::Label, Text, Punctuation, Name::Function, Operator,
                 Num::Hex, Punctuation, Punctuation
          push :instruction
        end
        rule %r/((?:0x)?\h+)([ \t]+)(<)([^<>\n]+)(>)(:?)/ do
          groups Name::Label, Text, Punctuation, Name::Function,
                 Punctuation, Punctuation
          push :instruction
        end

        # objdump instruction line: `  1f8a:\te8 51 f1 ff ff \tcall …`, and
        # gdb's `x/10i` form, which prefixes the same column with 0x.
        # The byte column is optional (`objdump -d --no-show-raw-insn`, and
        # every gdb variant, omit it), so :bytes falls through on no match.
        rule %r/((?:0x)?\h+)(:)/ do
          groups Name::Label, Punctuation
          push :bytes
        end

        # A continuation line of an instruction too long for one row: bare
        # byte pairs and nothing else.
        rule %r/(?:\h\h )*\h\h(?=[ \t]*$)/, Generic::Output

        # Prose between blocks (a writeup interleaves it), taken a whole line
        # at a time so nothing above can match in the middle of a sentence.
        rule %r/[^\n]+/, Text
      end

      # The opcode bytes, then the instruction. Byte pairs are required to be
      # single-space separated and followed by whitespace or EOL, so a
      # 4-letter all-hex mnemonic (`fadd`) is not mistaken for two bytes.
      state :bytes do
        rule %r/[ \t]+/, Text
        rule %r/\h\h(?: \h\h)*(?=[ \t]|$)/, Generic::Output
        rule %r/\n/, Text, :pop!
        # Nothing byte-shaped left: whatever follows is the instruction.
        rule(//) { goto :instruction }
      end

      state :instruction do
        rule %r/\n/, Text, :pop!
        rule %r/[ \t]+/, Text

        rule %r/(?:rep(?:n?[ez])?|lock|bnd|data16|addr32|rex(?:\.\w+)?)\b/i,
             Keyword::Reserved

        rule %r/[a-z][a-z0-9_.]*/i, Keyword, :operands
        rule %r/[^\n]/, Text
      end

      state :operands do
        # One newline leaves both :operands and the line's :instruction frame,
        # so every line starts again in :root and an address column can only
        # ever be recognised at a line start.
        rule %r/\n/ do
          token Text
          pop!(2)
        end

        rule %r/#[^\n]*/, Comment::Single
        rule %r/;[^\n]*/, Comment::Single

        # `<read@plt>` and `<main+0x8c>` — the branch target's symbol. This
        # is the one operand a reader actually navigates by.
        rule %r/(<)([^<>+\n]+)(\+)(0x\h+|\d+)(>)/ do
          groups Punctuation, Name::Function, Operator, Num::Hex, Punctuation
        end
        rule %r/(<)([^<>\n]+)(>)/ do
          groups Punctuation, Name::Function, Punctuation
        end

        rule PTR_SIZE, Keyword::Type

        # objdump prints a branch target as a bare hex address followed by the
        # symbol it lands in: `call   10e0 <read@plt>`. That is an address, not
        # an immediate, so it takes the address token — which is what the
        # approved PWN-06 specimen colours it as.
        rule %r/\b\h+(?=[ \t]*<)/, Name::Label

        rule %r/%#{REGISTER}/, Name::Variable     # AT&T
        rule %r/\$-?0x\h+/, Num::Hex              # AT&T immediate
        rule %r/\$-?\d+/, Num::Integer

        rule %r/-?0x\h+/, Num::Hex
        rule %r/\b\d+\b/, Num::Integer

        # Intel-syntax bare registers, after the numeric rules so `0x8` is
        # not read as a register fragment.
        rule %r/\b#{REGISTER}/, Name::Variable

        # A symbol operand that is not in <angle brackets> (gdb prints
        # `callq  0x555555555060 <read@plt>`, but `.plt` sections and
        # relocation stubs print bare names).
        rule %r/[a-z_.][\w.@$]*/i, Name::Other

        rule %r/[-+*,()\[\]:{}]/, Punctuation
        rule %r/[^\n]/, Text
      end

      # Everything after a debugger prompt is what the author typed.
      state :command do
        rule %r/\n/, Text, :pop!
        # gdb's convenience registers: `$pc`, `$rdi`, `$sp`.
        rule %r/\$\w+/, Name::Variable
        rule %r/0x\h+/, Num::Hex
        rule %r/[^\n]/, Text
      end
    end
  end
end
