#!/usr/bin/env python3
"""Embed the browser sources in firmware. --check is read-only (CI safe)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "PPS" / "web_assets.h"
DELIMITER = "PPSWEB"


def raw_asset(text: str) -> str:
    if f"){DELIMITER}\"" in text:
        raise ValueError("Web asset contains the C++ raw-string terminator")
    return f'R"{DELIMITER}({text}){DELIMITER}"'


def generate() -> str:
    index = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    script = (ROOT / "web" / "script.js").read_text(encoding="utf-8")
    style = (ROOT / "web" / "style.css").read_text(encoding="utf-8")
    strict_prefix = "'use strict';\n"
    if not script.startswith(strict_prefix):
        raise ValueError('script.js must start with a strict-mode directive')
    script = script[len(strict_prefix):]
    # The JS source refers to PPS_LIMITS. Keep these limits tied to config.h;
    # never hardcode a duplicate record or vault size in the browser.
    return (
        '#pragma once\n#include <Arduino.h>\n#include "config.h"\n'
        f'static const char WEB_INDEX[] PROGMEM =\n{raw_asset(index)};\n'
        'static const char WEB_SCRIPT[] PROGMEM =\n'
        '"\'use strict\';\\n"\n'
        '"const PPS_LIMITS=Object.freeze({maxEntries:" PPS_STRINGIFY(PPS_MAX_ENTRIES)\n'
        '",vaultBytes:" PPS_STRINGIFY(PPS_VAULT_MAX_BYTES) "});\\n"\n'
        f'{raw_asset(script)};\n'
        f'static const char WEB_STYLE[] PROGMEM =\n{raw_asset(style)};\n'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify generated file without changing it')
    args = parser.parse_args()
    try:
        expected = generate()
    except (OSError, UnicodeError, ValueError) as exc:
        print(f'Web assets: {exc}', file=sys.stderr)
        return 2
    current = TARGET.read_text(encoding='utf-8') if TARGET.exists() else None
    if args.check:
        if current != expected:
            print('web_assets.h is outdated; run python tools/embed_web.py', file=sys.stderr)
            return 1
        print('web_assets.h is up to date')
        return 0
    if current != expected:
        TARGET.write_text(expected, encoding='utf-8')
        print('Updated PPS/web_assets.h')
    else:
        print('PPS/web_assets.h is already up to date')
    return 0


if __name__ == '__main__':
    sys.exit(main())
