#!/usr/bin/env python3
"""Generate or verify PPS/web_assets.h from the three editable web sources.

Usage:
  python tools/embed_web.py
  python tools/embed_web.py --check  # non-mutating consistency check (CI)

PPS_LIMITS is compiled from config.h macros, not fixed JS literals.
"""
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'PPS' / 'web_assets.h'
WEB = ROOT / 'web'
DELIMITER = 'PPSWEB'
JS_PREFIX = "'use strict';\n"
JS_LIMITS = 'const PPS_LIMITS=Object.freeze({maxEntries:256,vaultBytes:32768});\n'


def get(name):
    text = (WEB / name).read_text(encoding='utf-8')
    if '\x00' in text or f'){DELIMITER}"' in text:
        raise ValueError(f'{name}: forbidden NUL or raw-string terminator')
    return text


def generate():
    index = get('index.html')
    script = get('script.js')
    style = get('style.css')
    if not script.startswith(JS_PREFIX + JS_LIMITS):
        raise ValueError('script.js must start with strict mode and the PPS_LIMITS test defaults')
    script = script[len(JS_PREFIX + JS_LIMITS):]
    # Config values in the firmware remain authoritative even if their
    # defaults are changed. The JS test defaults are for local JS checks only.
    return ('#pragma once\n#include <Arduino.h>\n#include "config.h"\n'
            f'static const char WEB_INDEX[] PROGMEM =\nR"{DELIMITER}({index}){DELIMITER}";\n'
            'static const char WEB_SCRIPT[] PROGMEM =\n'
            '"\'use strict\';\\n"\n'
            '"const PPS_LIMITS=Object.freeze({maxEntries:" PPS_STRINGIFY(PPS_MAX_ENTRIES)\n'
            '",vaultBytes:" PPS_STRINGIFY(PPS_VAULT_MAX_BYTES) "});\\n"\n'
            f'R"{DELIMITER}({script}){DELIMITER}";\n'
            f'static const char WEB_STYLE[] PROGMEM =\nR"{DELIMITER}({style}){DELIMITER}";\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify assets without modifying files')
    args = parser.parse_args()
    try:
        content = generate()
        if args.check:
            if not OUT.exists() or OUT.read_text(encoding='utf-8') != content:
                print('web_assets.h is out of date: run python tools/embed_web.py', file=sys.stderr)
                return 1
            print('web_assets.h matches the web sources')
        else:
            OUT.write_text(content, encoding='utf-8', newline='\n')
            print(f'Wrote {OUT.relative_to(ROOT)}')
        return 0
    except (OSError, ValueError) as exc:
        print(f'embed_web.py: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
