#!/usr/bin/env python3
"""Copy a partition CSV, removing only data/coredump rows.
Keeps every other line byte-for-byte; never overwrites a destination.
Does NOT flash or erase anything. Refuses ambiguous implicit offsets after removal.
"""
import argparse
import csv
from pathlib import Path

def remove_coredump(text:str)->str:
    output=[];removed=False
    for line in text.splitlines(keepends=True):
        stripped=line.strip()
        if not stripped or stripped.startswith('#'):
            output.append(line);continue
        fields=next(csv.reader([line]))
        if len(fields)<5:raise ValueError('Partition row has fewer than five columns')
        kind,subtype=fields[1].strip().lower(),fields[2].strip().lower()
        if kind in ('data','1','0x01','0x1') and subtype in ('coredump','3','0x03','0x3'):
            removed=True;continue
        if removed and not fields[3].strip():
            raise ValueError('An implicit offset follows the removed row; use explicit original offsets first')
        output.append(line)
    return ''.join(output)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('destination',type=Path);a=p.parse_args()
    try:
        source=a.source.read_bytes().decode('utf-8');result=remove_coredump(source)
        with a.destination.open('xb') as out:out.write(result.encode('utf-8'))
    except (OSError,ValueError) as e:p.exit(1,f'Error: {e}\n')
    print(f'Written: {a.destination}. Verify flash size and all offsets before uploading.')
if __name__=='__main__':main()
