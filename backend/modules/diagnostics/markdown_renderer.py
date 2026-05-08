import re

import bleach
import markdown


ALLOWED_TAGS = [
    "p",
    "br",
    "strong",
    "b",
    "em",
    "i",
    "u",
    "s",
    "blockquote",
    "code",
    "pre",
    "ul",
    "ol",
    "li",
    "hr",
    "h1",
    "h2",
    "h3",
    "h4",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "a",
]

ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "target", "rel"],
    "th": ["align"],
    "td": ["align"],
}

ALLOWED_PROTOCOLS = ["http", "https", "mailto"]
MARKDOWN_EXTENSIONS = ["extra", "tables", "fenced_code", "sane_lists"]


def _harden_links(html: str) -> str:
    def replace(match):
        attrs = match.group(1)
        attrs = re.sub(r'\s+(target|rel)=("[^"]*"|\'[^\']*\'|[^\s>]+)', "", attrs, flags=re.IGNORECASE)
        return f'<a{attrs} target="_blank" rel="noopener noreferrer nofollow">'

    return re.sub(r"<a\b([^>]*)>", replace, html, flags=re.IGNORECASE)


def render_markdown(content: str) -> dict:
    source = (content or "").strip()

    if not source:
        return {
            "error": True,
            "message": "Nenhum conteúdo Markdown foi enviado."
        }

    raw_html = markdown.markdown(
        source,
        extensions=MARKDOWN_EXTENSIONS,
        output_format="html",
    )

    clean_html = bleach.clean(
        raw_html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
    clean_html = _harden_links(clean_html)

    return {
        "error": False,
        "html": clean_html,
    }
