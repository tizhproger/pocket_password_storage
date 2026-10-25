#!/usr/bin/env python3
"""Usage: python tools/make_font.py path/to/DejaVuSansMono.ttf (Pillow)."""
from pathlib import Path
import sys
from PIL import Image, ImageDraw, ImageFont
font=ImageFont.truetype(sys.argv[1],10)
cps=[*range(32,127),*range(160,256),*range(0x400,0x500)]
out=Path(__file__).resolve().parents[1]/'SoloVault'/'record_font.h'
with out.open('w') as f:
 f.write('// Generated from DejaVu Sans Mono; see third_party/DejaVu-LICENSE.txt\n#pragma once\n#include <Arduino.h>\nstatic const uint8_t recordFont[][12] PROGMEM={\n')
 for cp in cps:
  image=Image.new('1',(8,12));ImageDraw.Draw(image).text((1,0),chr(cp),font=font,fill=1)
  rows=[sum(1<<(7-x) if image.getpixel((x,y)) else 0 for x in range(8)) for y in range(12)]
  f.write('{'+','.join(f'0x{b:02x}' for b in rows)+'}, // U+'+f'{cp:04X}'+'\n')
 f.write('};\ninline int recordGlyph(uint32_t cp){if(cp>=32&&cp<127)return cp-32;if(cp>=160&&cp<256)return 95+cp-160;if(cp>=0x400&&cp<0x500)return 191+cp-0x400;return -1;}\n')
