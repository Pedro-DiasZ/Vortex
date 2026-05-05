import html
import re


def _inline(text: str) -> str:
    text = html.escape(text or "")
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", text)
    text = re.sub(
        r"\[([^\]]+)\]\((https?://[^\s)]+)\)",
        r'<a href="\2" target="_blank" rel="noopener noreferrer">\1</a>',
        text,
    )
    return text


def render_markdown(markdown: str) -> dict:
    source = (markdown or "")[:100000]
    lines = source.splitlines()
    html_parts = []
    in_ul = False
    in_ol = False
    in_code = False
    code_lines = []
    table_buffer = []

    def close_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            html_parts.append("</ul>")
            in_ul = False
        if in_ol:
            html_parts.append("</ol>")
            in_ol = False

    def flush_table():
        nonlocal table_buffer
        if len(table_buffer) >= 2 and "|" in table_buffer[0] and re.match(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$", table_buffer[1]):
            close_lists()
            headers = [c.strip() for c in table_buffer[0].strip("|").split("|")]
            rows = [[c.strip() for c in row.strip("|").split("|")] for row in table_buffer[2:]]
            html_parts.append("<table><thead><tr>" + "".join(f"<th>{_inline(h)}</th>" for h in headers) + "</tr></thead><tbody>")
            for row in rows:
                html_parts.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in row) + "</tr>")
            html_parts.append("</tbody></table>")
        elif table_buffer:
            for row in table_buffer:
                html_parts.append(f"<p>{_inline(row)}</p>")
        table_buffer = []

    for line in lines:
        if line.strip().startswith("```"):
            flush_table()
            close_lists()
            if in_code:
                html_parts.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if "|" in line and line.strip():
            table_buffer.append(line)
            continue
        flush_table()
        stripped = line.strip()
        if not stripped:
            close_lists()
            continue
        if re.match(r"^-{3,}$", stripped):
            close_lists()
            html_parts.append("<hr>")
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if heading:
            close_lists()
            level = len(heading.group(1))
            html_parts.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            continue
        if stripped.startswith(">"):
            close_lists()
            html_parts.append(f"<blockquote>{_inline(stripped.lstrip('>').strip())}</blockquote>")
            continue
        bullet = re.match(r"^[-*]\s+(.+)$", stripped)
        if bullet:
            if not in_ul:
                close_lists()
                html_parts.append("<ul>")
                in_ul = True
            html_parts.append(f"<li>{_inline(bullet.group(1))}</li>")
            continue
        ordered = re.match(r"^\d+\.\s+(.+)$", stripped)
        if ordered:
            if not in_ol:
                close_lists()
                html_parts.append("<ol>")
                in_ol = True
            html_parts.append(f"<li>{_inline(ordered.group(1))}</li>")
            continue
        close_lists()
        html_parts.append(f"<p>{_inline(stripped)}</p>")

    if in_code:
        html_parts.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
    flush_table()
    close_lists()

    words = re.findall(r"\b[\wÀ-ÿ-]+\b", source, flags=re.UNICODE)
    return {
        "html": "\n".join(html_parts),
        "markdown": source,
        "characters": len(source),
        "words": len(words),
    }

