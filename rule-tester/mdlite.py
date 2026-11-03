"""Минимальный конвертер Markdown -> HTML, без внешних зависимостей.

Нужен только для того, чтобы показать docs/*.md прямо в веб-интерфейсе (страница
«Руководство администратора»). Поддерживает ровно то, что реально используется в этих
файлах: заголовки, абзацы, нумерованные и маркированные списки, блоки кода (```),
ссылки, картинки, **жирный**/*курсив*/`инлайн-код`. Не претендует на полный CommonMark —
таблиц, цитат, вложенных списков и экранирования обратным слэшем нет, потому что их нет
и в самих доках.
"""
import html
import re

_INLINE_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")
_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
_LINK = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_OL = re.compile(r"^\d+\.\s+(.*)$")
_UL = re.compile(r"^[-*]\s+(.*)$")


def _rewrite_href(url, image_base):
    """images/17-foo.png -> <image_base>17-foo.png; ссылки на другие главы (.md) не трогаем —
    открывать их всё равно негде внутри инструмента, пусть ведут на GitHub руками при желании."""
    if url.startswith("images/"):
        return image_base + url[len("images/"):]
    return url


def _inline(text, image_base):
    text = html.escape(text, quote=False)
    text = _IMAGE.sub(lambda m: '<img alt="%s" src="%s" loading="lazy">' % (
        html.escape(m.group(1), quote=True), _rewrite_href(m.group(2), image_base)), text)
    text = _LINK.sub(lambda m: '<a href="%s">%s</a>' % (
        _rewrite_href(m.group(2), image_base), m.group(1)), text)
    text = _INLINE_CODE.sub(lambda m: "<code>%s</code>" % m.group(1), text)
    text = _BOLD.sub(lambda m: "<strong>%s</strong>" % m.group(1), text)
    text = _ITALIC.sub(lambda m: "<em>%s</em>" % m.group(1), text)
    return text


def convert(md_text, image_base="/guide-images/"):
    lines = md_text.replace("\r\n", "\n").split("\n")
    out = []
    n = len(lines)
    i = 0
    list_tag = None

    def close_list():
        nonlocal list_tag
        if list_tag:
            out.append("</%s>" % list_tag)
            list_tag = None

    while i < n:
        raw = lines[i]
        stripped = raw.strip()

        if stripped.startswith("```"):
            close_list()
            i += 1
            code_lines = []
            while i < n and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1
            out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(code_lines)))
            continue

        if not stripped:
            close_list()
            i += 1
            continue

        m = _HEADING.match(stripped)
        if m:
            close_list()
            level = len(m.group(1))
            out.append("<h%d>%s</h%d>" % (level, _inline(m.group(2), image_base), level))
            i += 1
            continue

        m = _OL.match(stripped)
        if m:
            if list_tag != "ol":
                close_list()
                out.append("<ol>")
                list_tag = "ol"
            out.append("<li>%s</li>" % _inline(m.group(1), image_base))
            i += 1
            continue

        m = _UL.match(stripped)
        if m:
            if list_tag != "ul":
                close_list()
                out.append("<ul>")
                list_tag = "ul"
            out.append("<li>%s</li>" % _inline(m.group(1), image_base))
            i += 1
            continue

        close_list()
        para = [stripped]
        i += 1
        while i < n and lines[i].strip() and not lines[i].strip().startswith("```") \
                and not _HEADING.match(lines[i].strip()) and not _OL.match(lines[i].strip()) \
                and not _UL.match(lines[i].strip()):
            para.append(lines[i].strip())
            i += 1
        out.append("<p>%s</p>" % _inline(" ".join(para), image_base))

    close_list()
    return "\n".join(out)
