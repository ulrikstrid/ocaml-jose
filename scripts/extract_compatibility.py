#!/usr/bin/env python3
"""
extract_compatibility.py - Extract and maintain the JOSE algorithm compatibility table.

Extracts supported algorithms, content encryption algorithms, and key types
from the OCaml source code (jose/Jwa.ml, jose/Jose.mli) and compares them against
the standard RFC specifications (RFC 7518, RFC 8037, RFC 9864).

Can output markdown tables, update README.md in-place, check sync status in CI,
or output JSON.

Usage:
    # Print markdown table to stdout:
    python3 scripts/extract_compatibility.py

    # Update README.md in-place:
    python3 scripts/extract_compatibility.py --update-readme

    # Check if README.md is in sync (returns exit code 1 if out of sync):
    python3 scripts/extract_compatibility.py --check

    # Run self-tests:
    python3 scripts/extract_compatibility.py --test
"""

import argparse
import json
import os
import re
import sys
import unittest
from typing import Dict, List, Optional, Set, Tuple


START_MARKER = "<!-- COMPATIBILITY_TABLE_START -->"
END_MARKER = "<!-- COMPATIBILITY_TABLE_END -->"


# Standard RFC definitions: (Name, Description, Implementation Requirement, RFC Reference, RFC URL)
STANDARD_JWS_ALGS = [
    ("HS256", "HMAC using SHA-256", "Required", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("HS384", "HMAC using SHA-384", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("HS512", "HMAC using SHA-512", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("RS256", "RSASSA-PKCS1-v1_5 using SHA-256", "Recommended", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("RS384", "RSASSA-PKCS1-v1_5 using SHA-384", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("RS512", "RSASSA-PKCS1-v1_5 using SHA-512", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("ES256", "ECDSA using P-256 and SHA-256", "Recommended+", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("ES384", "ECDSA using P-384 and SHA-384", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("ES512", "ECDSA using P-521 and SHA-512", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("PS256", "RSASSA-PSS using SHA-256 and MGF1 with SHA-256", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("PS384", "RSASSA-PSS using SHA-384 and MGF1 with SHA-384", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("PS512", "RSASSA-PSS using SHA-512 and MGF1 with SHA-512", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
    ("EdDSA", "EdDSA signature algorithm (deprecated by RFC 9864)", "Optional", "RFC 8037 §3.1", "https://www.rfc-editor.org/info/rfc8037/#section-3.1"),
    ("Ed25519", "Ed25519 signature algorithm", "Optional", "RFC 9864 §3.1", "https://www.rfc-editor.org/info/rfc9864/#section-3.1"),
    ("Ed448", "Ed448 signature algorithm", "Optional", "RFC 9864 §3.1", "https://www.rfc-editor.org/info/rfc9864/#section-3.1"),
    ("none", "No digital signature or MAC performed", "Optional", "RFC 7518 §3.1", "https://www.rfc-editor.org/info/rfc7518/#section-3.1"),
]

STANDARD_JWE_KM_ALGS = [
    ("RSA1_5", "RSAES-PKCS1-v1_5", "Recommended-", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("RSA-OAEP", "RSAES OAEP using default parameters", "Recommended+", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("RSA-OAEP-256", "RSAES OAEP using SHA-256 and MGF1 with SHA-256", "Optional", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("A128KW", "AES Key Wrap using 128-bit key", "Recommended", "RFC 7518 §4.1, RFC 3394", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("A192KW", "AES Key Wrap using 192-bit key", "Optional", "RFC 7518 §4.1, RFC 3394", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("A256KW", "AES Key Wrap using 256-bit key", "Recommended", "RFC 7518 §4.1, RFC 3394", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("dir", "Direct use of a shared symmetric key", "Recommended", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("ECDH-ES", "Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF", "Recommended+", "RFC 7518 §4.1, §4.6", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("ECDH-ES+A128KW", "ECDH-ES using Concat KDF and CEK wrapped with \"A128KW\"", "Recommended", "RFC 7518 §4.1, §4.6", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("ECDH-ES+A192KW", "ECDH-ES using Concat KDF and CEK wrapped with \"A192KW\"", "Optional", "RFC 7518 §4.1, §4.6", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("ECDH-ES+A256KW", "ECDH-ES using Concat KDF and CEK wrapped with \"A256KW\"", "Recommended", "RFC 7518 §4.1, §4.6", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("A128GCMKW", "Key wrapping with AES GCM using 128-bit key", "Optional", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("A192GCMKW", "Key wrapping with AES GCM using 192-bit key", "Optional", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("A256GCMKW", "Key wrapping with AES GCM using 256-bit key", "Optional", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("PBES2-HS256+A128KW", "PBES2 with HMAC SHA-256 and \"A128KW\" wrapping", "Optional", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("PBES2-HS384+A192KW", "PBES2 with HMAC SHA-384 and \"A192KW\" wrapping", "Optional", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
    ("PBES2-HS512+A256KW", "PBES2 with HMAC SHA-512 and \"A256KW\" wrapping", "Optional", "RFC 7518 §4.1", "https://www.rfc-editor.org/info/rfc7518/#section-4.1"),
]

STANDARD_JWE_ENC_ALGS = [
    ("A128CBC-HS256", "AES_128_CBC_HMAC_SHA_256 authenticated encryption", "Required", "RFC 7518 §5.1, §5.2.3", "https://www.rfc-editor.org/info/rfc7518/#section-5.1"),
    ("A192CBC-HS384", "AES_192_CBC_HMAC_SHA_384 authenticated encryption", "Optional", "RFC 7518 §5.1, §5.2.4", "https://www.rfc-editor.org/info/rfc7518/#section-5.1"),
    ("A256CBC-HS512", "AES_256_CBC_HMAC_SHA_512 authenticated encryption", "Required", "RFC 7518 §5.1, §5.2.5", "https://www.rfc-editor.org/info/rfc7518/#section-5.1"),
    ("A128GCM", "AES GCM using 128-bit key", "Recommended", "RFC 7518 §5.1, §5.3", "https://www.rfc-editor.org/info/rfc7518/#section-5.1"),
    ("A192GCM", "AES GCM using 192-bit key", "Optional", "RFC 7518 §5.1, §5.3", "https://www.rfc-editor.org/info/rfc7518/#section-5.1"),
    ("A256GCM", "AES GCM using 256-bit key", "Recommended", "RFC 7518 §5.1, §5.3", "https://www.rfc-editor.org/info/rfc7518/#section-5.1"),
]

STANDARD_JWK_KTYS = [
    ("EC", "Elliptic Curve", "Recommended+", "RFC 7518 §6.1", "https://www.rfc-editor.org/info/rfc7518/#section-6.1"),
    ("RSA", "RSA", "Required", "RFC 7518 §6.1", "https://www.rfc-editor.org/info/rfc7518/#section-6.1"),
    ("oct", "Octet sequence (used to represent symmetric keys)", "Required", "RFC 7518 §6.1", "https://www.rfc-editor.org/info/rfc7518/#section-6.1"),
    ("OKP", "Octet Key Pair", "Optional", "RFC 8037 §2", "https://www.rfc-editor.org/info/rfc8037/#section-2"),
]


def extract_variant_mappings(func_name: str, text: str) -> Dict[str, str]:
    """Extract polymorphic variant to string mappings from Jwa.ml."""
    pattern = rf"let\s+{func_name}\b[^=]*=\s*(?:function|match\s+\w+\s+with)\s*(.+?)(?=\nlet|\Z)"
    m = re.search(pattern, text, re.DOTALL)
    if not m:
        return {}
    body = m.group(1)
    mapping = {}
    for line in body.splitlines():
        match = re.search(r"\|\s*`([A-Za-z0-9_]+)\s*->\s*\"([^\"]+)\"", line)
        if match:
            variant, val = match.groups()
            if variant != "Unsupported":
                mapping[variant] = val
    return mapping


def parse_mli_docstrings(text: str) -> Dict[str, Tuple[str, str, str]]:
    """
    Parse variant docstrings from Jose.mli.
    Returns variant -> (description, requirement, rfc_ref).
    """
    pattern = r"(?:\||\[)\s*`([A-Za-z0-9_]+)\s*\(\*\*\s*(.+?)\s*\*\)"
    docs = {}
    for m in re.finditer(pattern, text, re.DOTALL):
        variant = m.group(1)
        raw_doc = " ".join(m.group(2).split())
        # Example doc: "HMAC using SHA-256 - Required ({{:...} RFC 7518 §3.1})"
        req_match = re.search(r"-\s*(Required|Recommended[+-]?|Optional)", raw_doc, re.IGNORECASE)
        requirement = req_match.group(1) if req_match else "Optional"

        # Split description before requirement
        if req_match:
            desc = raw_doc[:req_match.start()].strip(" -")
        else:
            desc = raw_doc

        # Extract RFC ref
        rfc_match = re.search(r"RFC\s+\d+(?:\s*§[\d\.]+)?", raw_doc)
        rfc_ref = rfc_match.group(0) if rfc_match else ""

        docs[variant] = (desc, requirement, rfc_ref)
    return docs


def extract_supported_from_code(jwa_content: str, mli_content: str) -> Dict[str, Set[str]]:
    """
    Extract supported signature algorithms, key management algorithms,
    content encryption algorithms, and key types.
    """
    alg_map = extract_variant_mappings("alg_to_string", jwa_content)
    enc_map = extract_variant_mappings("enc_to_string", jwa_content)
    kty_map = extract_variant_mappings("kty_to_string", jwa_content)

    # In Jose.mli, signature vs key management algorithms are documented:
    sig_algs_set: Set[str] = set()
    km_algs_set: Set[str] = set()

    sig_match = re.search(r"Signature algorithms supported:\s*([^.]+)\.", mli_content)
    if sig_match:
        for x in re.findall(r"\[([A-Za-z0-9_]+)\]", sig_match.group(1)):
            if x in alg_map:
                sig_algs_set.add(alg_map[x])
            else:
                sig_algs_set.add(x)

    km_match = re.search(r"Key management algorithms supported:\s*([^.]+)\.", mli_content)
    if km_match:
        for x in re.findall(r"\[([A-Za-z0-9_]+)\]", km_match.group(1)):
            if x in alg_map:
                km_algs_set.add(alg_map[x])
            else:
                km_algs_set.add(x)

    # If 'None' / 'none' is in alg_map, it is supported for unsigned JWTs
    if "None" in alg_map:
        sig_algs_set.add("none")

    # Fallback / heuristic if Jose.mli comment was missing or incomplete:
    # Any alg in alg_map not in km_algs_set or sig_algs_set is checked against standard lists
    for var, name in alg_map.items():
        if name not in sig_algs_set and name not in km_algs_set:
            if any(name == std[0] for std in STANDARD_JWS_ALGS):
                sig_algs_set.add(name)
            elif any(name == std[0] for std in STANDARD_JWE_KM_ALGS):
                km_algs_set.add(name)

    enc_set = set(enc_map.values())
    kty_set = set(kty_map.values())

    return {
        "jws_alg": sig_algs_set,
        "jwe_km_alg": km_algs_set,
        "jwe_enc": enc_set,
        "jwk_kty": kty_set,
    }


def build_category_table(
    standards: List[Tuple[str, str, str, str, str]],
    supported_set: Set[str],
) -> List[Dict[str, str]]:
    """Build list of dict rows for a table given standard items and supported set."""
    rows = []
    seen = set()

    # Add standard items
    for name, desc, req, rfc_ref, rfc_url in standards:
        is_supported = name in supported_set
        seen.add(name)
        rows.append({
            "name": name,
            "description": desc,
            "requirement": req,
            "rfc_ref": rfc_ref,
            "rfc_url": rfc_url,
            "supported": "Yes" if is_supported else "No",
        })

    # If any algorithms are supported in code that weren't in standards, append them
    for name in sorted(supported_set):
        if name not in seen:
            rows.append({
                "name": name,
                "description": f"Custom / extension algorithm ({name})",
                "requirement": "Extension",
                "rfc_ref": "Extension",
                "rfc_url": "",
                "supported": "Yes",
            })

    return rows


def generate_all_tables(repo_root: str) -> Dict[str, List[Dict[str, str]]]:
    """Load sources from repo and generate tables data dictionary."""
    jwa_path = os.path.join(repo_root, "jose", "Jwa.ml")
    mli_path = os.path.join(repo_root, "jose", "Jose.mli")

    with open(jwa_path, "r", encoding="utf-8") as f:
        jwa_content = f.read()
    with open(mli_path, "r", encoding="utf-8") as f:
        mli_content = f.read()

    supported = extract_supported_from_code(jwa_content, mli_content)

    return {
        "jws_algs": build_category_table(STANDARD_JWS_ALGS, supported["jws_alg"]),
        "jwe_km_algs": build_category_table(STANDARD_JWE_KM_ALGS, supported["jwe_km_alg"]),
        "jwe_enc_algs": build_category_table(STANDARD_JWE_ENC_ALGS, supported["jwe_enc"]),
        "jwk_ktys": build_category_table(STANDARD_JWK_KTYS, supported["jwk_kty"]),
    }


def make_rfc_link(ref: str, url: str) -> str:
    """Format an RFC reference as a Markdown link if URL is provided."""
    if not url or not ref:
        return ref

    # Handle multi-part references like "RFC 7518 §4.1, RFC 3394"
    if ", RFC 3394" in ref:
        return f"[{ref.split(',')[0]}](https://www.rfc-editor.org/info/rfc7518/#section-4.1), [RFC 3394](https://www.rfc-editor.org/info/rfc3394)"
    if ", §4.6" in ref:
        base = ref.split(",")[0].strip()
        return f"[{base}]({url}), [§4.6](https://www.rfc-editor.org/info/rfc7518/#section-4.6)"
    if ", §5.2." in ref:
        parts = ref.split(",")
        base = parts[0].strip()
        sec = parts[1].strip()
        sec_num = sec.lstrip("§")
        return f"[{base}]({url}), [{sec}](https://www.rfc-editor.org/info/rfc7518/#section-{sec_num})"
    if ", §5.3" in ref:
        return f"[{ref.split(',')[0].strip()}]({url}), [§5.3](https://www.rfc-editor.org/info/rfc7518/#section-5.3)"

    return f"[{ref}]({url})"


def format_markdown(tables: Dict[str, List[Dict[str, str]]]) -> str:
    """Render the compatibility tables in clean GitHub-Flavored Markdown."""
    sections = []

    # 1. JWS Algorithms
    jws_rows = [
        f"| `{r['name']}` | {r['description']} | {r['requirement']} | {make_rfc_link(r['rfc_ref'], r['rfc_url'])} | {r['supported']} |"
        for r in tables["jws_algs"]
    ]
    sections.append(
        "### JWS Digital Signature and MAC Algorithms (`alg`)\n\n"
        "| Algorithm | Description | Requirement | RFC Reference | Supported |\n"
        "| :--- | :--- | :--- | :--- | :---: |\n" + "\n".join(jws_rows)
    )

    # 2. JWE Key Management Algorithms
    jwe_km_rows = [
        f"| `{r['name']}` | {r['description']} | {r['requirement']} | {make_rfc_link(r['rfc_ref'], r['rfc_url'])} | {r['supported']} |"
        for r in tables["jwe_km_algs"]
    ]
    sections.append(
        "### JWE Key Management Algorithms (`alg`)\n\n"
        "| Algorithm | Key Management Algorithm | Requirement | RFC Reference | Supported |\n"
        "| :--- | :--- | :--- | :--- | :---: |\n" + "\n".join(jwe_km_rows)
    )

    # 3. JWE Content Encryption Algorithms
    jwe_enc_rows = [
        f"| `{r['name']}` | {r['description']} | {r['requirement']} | {make_rfc_link(r['rfc_ref'], r['rfc_url'])} | {r['supported']} |"
        for r in tables["jwe_enc_algs"]
    ]
    sections.append(
        "### JWE Content Encryption Algorithms (`enc`)\n\n"
        "| Algorithm | Content Encryption Algorithm | Requirement | RFC Reference | Supported |\n"
        "| :--- | :--- | :--- | :--- | :---: |\n" + "\n".join(jwe_enc_rows)
    )

    # 4. JWK Key Types
    jwk_rows = [
        f"| `{r['name']}` | {r['description']} | {r['requirement']} | {make_rfc_link(r['rfc_ref'], r['rfc_url'])} | {r['supported']} |"
        for r in tables["jwk_ktys"]
    ]
    sections.append(
        "### JSON Web Key Types (`kty`)\n\n"
        "| Key Type (`kty`) | Description | Requirement | RFC Reference | Supported |\n"
        "| :--- | :--- | :--- | :--- | :---: |\n" + "\n".join(jwk_rows)
    )

    return "\n\n".join(sections)


def update_readme_content(content: str, table_markdown: str) -> str:
    """Inject or replace the compatibility table inside START/END markers in README content."""
    replacement = f"{START_MARKER}\n\n{table_markdown}\n\n{END_MARKER}"

    if START_MARKER in content and END_MARKER in content:
        pattern = re.compile(
            re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
            re.DOTALL,
        )
        return pattern.sub(replacement, content)

    # If markers not present, append under a new section
    return content.rstrip() + f"\n\n## Algorithm Compatibility\n\n{replacement}\n"


def find_repo_root() -> str:
    """Find the root of the repository based on file existence."""
    candidate = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.exists(os.path.join(candidate, "jose", "Jwa.ml")):
        return candidate
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, "jose", "Jwa.ml")):
        return cwd
    return candidate


class TestExtractCompatibility(unittest.TestCase):
    def test_extract_variant_mappings(self):
        sample = """
let alg_to_string = function
  | `RS256 -> "RS256"
  | `Dir -> "dir"
  | `ECDH_ES_A128KW -> "ECDH-ES+A128KW"
  | `Unsupported str -> str
"""
        mapping = extract_variant_mappings("alg_to_string", sample)
        self.assertEqual(mapping.get("RS256"), "RS256")
        self.assertEqual(mapping.get("Dir"), "dir")
        self.assertEqual(mapping.get("ECDH_ES_A128KW"), "ECDH-ES+A128KW")
        self.assertNotIn("Unsupported", mapping)

    def test_update_readme_content(self):
        initial = "# My Project\n\nIntro text.\n"
        tables = "### Table\n\n| Col |"
        updated = update_readme_content(initial, tables)
        self.assertIn(START_MARKER, updated)
        self.assertIn(END_MARKER, updated)
        self.assertIn("### Table", updated)

        # Updating again should replace the block cleanly
        updated2 = update_readme_content(updated, "### Updated Table")
        self.assertIn("### Updated Table", updated2)
        self.assertNotIn("### Table\n", updated2)

    def test_build_category_table(self):
        standards = [("HS256", "HMAC", "Required", "RFC 7518", "http://example.com")]
        supported = {"HS256"}
        table = build_category_table(standards, supported)
        self.assertEqual(len(table), 1)
        self.assertEqual(table[0]["supported"], "Yes")

        table_unsupported = build_category_table(standards, set())
        self.assertEqual(table_unsupported[0]["supported"], "No")


def main():
    parser = argparse.ArgumentParser(
        description="Extract and verify algorithm compatibility tables from OCaml sources and RFCs."
    )
    parser.add_argument(
        "--repo-root",
        default=find_repo_root(),
        help="Path to repository root (defaults to detected repo root).",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "--update-readme",
        action="store_true",
        help="Update README.md in-place with generated compatibility tables.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check whether README.md contains up-to-date compatibility tables. Exits 1 if out of sync.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write output to specified file instead of stdout.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run self-tests and exit.",
    )

    args = parser.parse_args()

    if args.test:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestExtractCompatibility)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    repo_root = os.path.abspath(args.repo_root)
    tables = generate_all_tables(repo_root)

    if args.format == "json":
        output_content = json.dumps(tables, indent=2)
    else:
        output_content = format_markdown(tables)

    readme_path = os.path.join(repo_root, "README.md")

    if args.check:
        if not os.path.exists(readme_path):
            sys.stderr.write(f"Error: {readme_path} does not exist.\n")
            sys.exit(1)
        with open(readme_path, "r", encoding="utf-8") as f:
            content = f.read()

        expected = update_readme_content(content, output_content)
        if content != expected:
            sys.stderr.write("README.md compatibility table is out of sync! Run with --update-readme to sync.\n")
            sys.exit(1)
        else:
            print("README.md compatibility table is up to date.")
            sys.exit(0)

    if args.update_readme:
        if not os.path.exists(readme_path):
            sys.stderr.write(f"Error: {readme_path} does not exist.\n")
            sys.exit(1)
        with open(readme_path, "r", encoding="utf-8") as f:
            content = f.read()

        updated = update_readme_content(content, output_content)
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(updated)
        print(f"Updated {readme_path} with latest compatibility tables.")
        return

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_content + "\n")
    else:
        print(output_content)


if __name__ == "__main__":
    main()
