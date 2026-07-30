# frozen_string_literal: true

# ===========================================================================
# _plugins/code_file_tag.rb — {% code_file <path> [lang=<lexer>] %}
#
# Renders a real file from the repo inline, syntax-highlighted, and links the
# same file as a download. One source of truth for both.
#
#   {% code_file exploits/madcore/exploit.py %}
#   {% code_file exploits/madcore/exploit.py lang=python %}
#
# WHY: today the madcore exploit exists only as fenced markdown inside the
# post, and the handout is linked to https://embe221ed.dev/files/… — a host
# outside this repo, which can break the post without anything here changing.
# A file in the repo is rendered, downloadable, diffable and greppable, and
# `bundle exec jekyll build` fails loudly if it goes missing.
#
# The emitted markup is exactly what kramdown + Rouge emit for a fenced
# block —
#
#   div.language-<tag>.highlighter-rouge
#     > div.highlight > pre.highlight > code
#
# — so every rule in assets/css/syntax.css applies unchanged, and the line
# wrapper in _plugins/code_lines.rb picks these blocks up too. The download
# line is a sibling of that div, not inside it, so the framed code block is
# untouched; it degrades to a plain link and a size when unstyled.
#
# Failure is inline and visible: a missing or unreadable file renders a
# `code_file: … not found` paragraph and logs a build warning. It never
# raises — a broken path must not be able to take the site down, and a
# silent empty block would be worse than either.
# ===========================================================================

require 'cgi'
require 'rouge'

module Interdot
  class CodeFileTag < Liquid::Tag
    SYNTAX = /\A(?<path>\S+)(?:\s+lang=(?<lang>[\w+#.-]+))?\s*\z/

    def initialize(tag_name, markup, tokens)
      super
      @markup = markup.to_s.strip.gsub(/\A["']|["']\z/, '')
    end

    def render(context)
      site = context.registers[:site]
      match = SYNTAX.match(@markup)
      return error("could not parse #{@markup.inspect}") if match.nil?

      relative = match[:path]
      absolute = resolve(site, relative)
      return error("#{relative} is outside the site source") if absolute.nil?
      return error("#{relative} not found") unless File.file?(absolute)

      # scrub: a file that is not valid UTF-8 is not a file to render inline
      # (the registry's own rule for this tag is "exploits yes, handouts no"),
      # but it must degrade to mojibake rather than to a raised EncodingError.
      # The download link still serves the real bytes either way.
      source = File.read(absolute).scrub
      track_dependency(site, context, absolute)
      block(site, relative, source, File.size(absolute), match[:lang])
    rescue StandardError => e
      error("#{@markup} could not be rendered (#{e.class})")
    end

    private

    # Everything is resolved under site.source, and a path that escapes it —
    # `../../etc/passwd`, or an absolute path — is refused rather than read.
    def resolve(site, relative)
      root = File.expand_path(site.source)
      path = File.expand_path(File.join(root, relative))
      path.start_with?("#{root}/") ? path : nil
    end

    def block(site, relative, source, bytes, lang)
      lexer = lexer_for(relative, source, lang)
      code = Rouge::Formatters::HTML.new.format(lexer.lex(source))
      meta = "#{human_size(bytes)} · #{source.count("\n")} lines"

      # One line, no newlines between the tags: kramdown passes a block-level
      # raw HTML element through untouched, and the div.highlight regex in
      # _plugins/code_lines.rb matches this exact nesting.
      %(<div class="code-file">) +
        %(<div class="language-#{lexer.tag} highlighter-rouge">) +
        %(<div class="highlight"><pre class="highlight"><code>#{code}</code></pre></div>) +
        %(</div>) +
        %(<p class="code-file__meta">) +
        %(<a class="code-file__dl" href="#{href(site, relative)}" ) +
        %(download="#{File.basename(relative)}">download #{relative}</a> ) +
        %(<span class="code-file__size">#{meta}</span></p></div>)
    end

    # The extension decides, with the file's own content as the tie-breaker;
    # `lang=` overrides both. Rouge raises Guesser::Ambiguous when two
    # lexers claim an extension, which is a guess, not a build error.
    def lexer_for(relative, source, lang)
      if lang
        found = Rouge::Lexer.find(lang)
        return found.new if found

        Jekyll.logger.warn 'code_file:', "no Rouge lexer tagged #{lang}, falling back"
      end

      Rouge::Lexer.guess(filename: File.basename(relative), source: source).new
    rescue Rouge::Guesser::Ambiguous => e
      e.alternatives.first.new
    rescue StandardError
      Rouge::Lexers::PlainText.new
    end

    def href(site, relative)
      baseurl = site.config['baseurl'].to_s.chomp('/')
      "#{baseurl}/#{relative}"
    end

    # Registers the rendered file with the regenerator so that editing the
    # exploit rebuilds the post under `jekyll build --incremental`, which
    # otherwise only watches the markdown.
    def track_dependency(site, context, absolute)
      page = context.registers[:page]
      return unless page && page['path'] && site.respond_to?(:regenerator)

      site.regenerator.add_dependency(site.in_source_dir(page['path']), absolute)
    rescue StandardError
      nil # a metadata optimisation, never a reason to fail a render
    end

    def human_size(bytes)
      return "#{bytes} B" if bytes < 1024

      format('%.1f KB', bytes / 1024.0)
    end

    def error(message)
      Jekyll.logger.warn 'code_file:', message
      '<div class="code-file code-file--missing"><p class="code-file__error">' \
        "<strong>code_file:</strong> #{CGI.escape_html(message)}</p></div>"
    end
  end
end

Liquid::Template.register_tag('code_file', Interdot::CodeFileTag)
