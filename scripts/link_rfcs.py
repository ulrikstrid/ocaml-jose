#!/usr/bin/env python3
"""
link_rfcs.py - Convert RFC references to odoc links.

Example:
    "RFC 7515 §4.1.10" -> "{{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.10} RFC 7515 §4.1.10}"

Note on odoc link syntax:
    odoc requires the leading colon in {{:URL} Text} to generate an HTML <a> link.
    Without the colon ({{URL} Text}), odoc treats it as inline code / verbatim.
    Use --no-colon if you specifically require {{URL} Text} without the leading colon.
"""

import argparse
import re
import sys
import unittest


# Regex pattern explanation:
# 1. First alternative: match existing odoc link structures so they are not modified:
#    {{:https://...} ...} or {{https://...} ...}
# 2. Second alternative: match RFC references:
#    - "RFC <number>"
#    - optionally followed by section (§ or Section) and section number
#    - optionally followed by chained sections separated by commas or slashes (e.g. ", §4.6" or "/§6.2.1.3")
PATTERN = re.compile(
    r'(\{\{[:]?https?://[^\s{}]+[ \t]*\}[^}]*\})|'
    r'(RFC\s+(\d+)(?:(\s*(?:§|Section\s+)([\d\.]+))((?:\s*[,/]\s*§\s*[\d\.]+)*))?)'
)


def linkify_rfc(text: str, use_colon: bool = True) -> str:
    colon = ":" if use_colon else ""

    def repl(m: re.Match) -> str:
        # If it matched an already linked block, preserve it unchanged
        if m.group(1):
            return m.group(1)

        rfc_num = m.group(3)
        has_section = m.group(4)
        first_sec = m.group(5)
        extra_secs = m.group(6)

        if not has_section:
            url = f"https://www.rfc-editor.org/info/rfc{rfc_num}"
            return f"{{{{{colon}{url}}} RFC {rfc_num}}}"

        # Preserve the section symbol / notation (normalize 'Section ' to '§' or keep)
        first_url = f"https://www.rfc-editor.org/info/rfc{rfc_num}/#section-{first_sec}"
        res = f"{{{{{colon}{first_url}}} RFC {rfc_num} §{first_sec}}}"

        if extra_secs:
            for delim, sec in re.findall(r"(\s*[,/]\s*)§\s*([\d\.]+)", extra_secs):
                sec_url = f"https://www.rfc-editor.org/info/rfc{rfc_num}/#section-{sec}"
                res += f"{delim}{{{{{colon}{sec_url}}} §{sec}}}"

        return res

    return PATTERN.sub(repl, text)


class TestLinkifyRFC(unittest.TestCase):
    def test_single_rfc_section(self):
        self.assertEqual(
            linkify_rfc("RFC 7515 §4.1.10"),
            "{{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.10} RFC 7515 §4.1.10}",
        )

    def test_single_rfc_section_no_colon(self):
        self.assertEqual(
            linkify_rfc("RFC 7515 §4.1.10", use_colon=False),
            "{{https://www.rfc-editor.org/info/rfc7515/#section-4.1.10} RFC 7515 §4.1.10}",
        )

    def test_single_rfc_no_section(self):
        self.assertEqual(
            linkify_rfc("RFC 7517"),
            "{{:https://www.rfc-editor.org/info/rfc7517} RFC 7517}",
        )

    def test_multiple_rfcs_in_string(self):
        inp = "RFC 7515 §4.1.1, RFC 7516 §4.1.1"
        expected = (
            "{{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.1} RFC 7515 §4.1.1}, "
            "{{:https://www.rfc-editor.org/info/rfc7516/#section-4.1.1} RFC 7516 §4.1.1}"
        )
        self.assertEqual(linkify_rfc(inp), expected)

    def test_multiple_sections_comma(self):
        inp = "RFC 7518 §4.1, §4.6"
        expected = (
            "{{:https://www.rfc-editor.org/info/rfc7518/#section-4.1} RFC 7518 §4.1}, "
            "{{:https://www.rfc-editor.org/info/rfc7518/#section-4.6} §4.6}"
        )
        self.assertEqual(linkify_rfc(inp), expected)

    def test_multiple_sections_slash(self):
        inp = "RFC 7518 §6.2.1.2/§6.2.1.3"
        expected = (
            "{{:https://www.rfc-editor.org/info/rfc7518/#section-6.2.1.2} RFC 7518 §6.2.1.2}/"
            "{{:https://www.rfc-editor.org/info/rfc7518/#section-6.2.1.3} §6.2.1.3}"
        )
        self.assertEqual(linkify_rfc(inp), expected)

    def test_section_word(self):
        inp = "RFC 3394 Section 2.2.1"
        expected = "{{:https://www.rfc-editor.org/info/rfc3394/#section-2.2.1} RFC 3394 §2.2.1}"
        self.assertEqual(linkify_rfc(inp), expected)

    def test_idempotent_already_linked(self):
        inp1 = "{{:https://www.rfc-editor.org/info/rfc7518/#section-3.1} RFC 7518 §3.1}"
        self.assertEqual(linkify_rfc(inp1), inp1)

        inp2 = "{{https://www.rfc-editor.org/info/rfc7518/#section-3.1} RFC 7518 §3.1}"
        self.assertEqual(linkify_rfc(inp2), inp2)

    def test_mixed_text(self):
        inp = "alg : Jwa.alg; (** Algorithm Header Parameter (RFC 7515 §4.1.1, RFC 7516 §4.1.1) *)"
        expected = (
            "alg : Jwa.alg; (** Algorithm Header Parameter ("
            "{{:https://www.rfc-editor.org/info/rfc7515/#section-4.1.1} RFC 7515 §4.1.1}, "
            "{{:https://www.rfc-editor.org/info/rfc7516/#section-4.1.1} RFC 7516 §4.1.1}) *)"
        )
        self.assertEqual(linkify_rfc(inp), expected)


def main():
    parser = argparse.ArgumentParser(
        description="Convert RFC references (e.g. 'RFC 7515 §4.1.10') to odoc link syntax."
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="File(s) to process. If none given, reads from standard input.",
    )
    parser.add_argument(
        "-i",
        "--in-place",
        action="store_true",
        help="Modify files in place.",
    )
    parser.add_argument(
        "--no-colon",
        action="store_true",
        help="Omit the leading colon in odoc link syntax ({{https://...}} instead of {{:https://...}}). "
        "Note: odoc requires the colon to render an HTML <a> link.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run self-tests and exit.",
    )

    args = parser.parse_args()

    if args.test:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestLinkifyRFC)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    use_colon = not args.no_colon

    if not args.files:
        content = sys.stdin.read()
        sys.stdout.write(linkify_rfc(content, use_colon=use_colon))
        return

    for path in args.files:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        transformed = linkify_rfc(content, use_colon=use_colon)

        if args.in_place:
            if transformed != content:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(transformed)
        else:
            sys.stdout.write(transformed)


if __name__ == "__main__":
    main()
