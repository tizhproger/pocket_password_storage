from pathlib import Path
root = Path(__file__).resolve().parent.parent
parts = ['#pragma once\n#include <Arduino.h>\n']
for name, filename in [('INDEX','index.html'),('SCRIPT','script.js'),('STYLE','style.css')]:
    text = (root/'web'/filename).read_text(encoding='utf-8')
    if ')PPSWEB"' in text:
        raise ValueError('Asset contains raw string delimiter')
    parts.append(f'static const char WEB_{name}[] PROGMEM = R"PPSWEB({text})PPSWEB";\n')
target=root/'PPS'/'web_assets.h'
content=''.join(parts)
if not target.exists() or target.read_text(encoding='utf-8') != content:
    target.write_text(content, encoding='utf-8')
