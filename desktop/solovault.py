#!/usr/bin/env python3
"""SoloVault USB client. Owner codes and stored-password export are not supported."""
from __future__ import annotations
import argparse
import getpass
import hashlib
import os
from pathlib import Path
import secrets
import struct
import sys
import time
import zlib

BLOB_MAX=12460
WIRE_MAX=BLOB_MAX+64
RESULTS=('OK','Locked / USB window closed','Invalid request','Another approval is pending',
         'Revision conflict; refresh list','Denied locally','Storage write failed','Storage damaged',
         'Storage full','Pending','Enter key on device','Approval expired')
STATES=('Empty','Ready','Recovery required','Foreign files','Corrupt','Unavailable')
ACCESS=('Closed','Backup','Manage','Restore')
OP_STATUS,OP_LIST,OP_PUT,OP_DELETE,OP_BACKUP,OP_RESTORE=1,16,17,18,32,33

class VaultError(Exception):
    pass

def frame(op:int,request_id:int,payload:bytes=b'')->bytes:
    if len(payload)>WIRE_MAX:raise VaultError('Request is too large')
    body=b'SVC1'+struct.pack('<BIH',op,request_id,len(payload))+payload
    return body+struct.pack('<I',zlib.crc32(body))

def validate_backup(data:bytes)->dict:
    if not 166<=len(data)<=BLOB_MAX or data[:8]!=b'SOLOV1\r\n':
        raise VaultError('Not a SoloVault v1 encrypted snapshot')
    version,generation,size,rounds=struct.unpack_from('<IIII',data,8)
    if version!=1 or not generation or not 10<=size<=12304 or rounds!=100000:
        raise VaultError('Unsupported or invalid snapshot parameters')
    if len(data)!=100+size+56 or data[-40:-32]!=b'SVCOMMIT':raise VaultError('Incomplete snapshot')
    if not secrets.compare_digest(hashlib.sha256(data[:-32]).digest(),data[-32:]):
        raise VaultError('Backup checksum mismatch')
    # SHA detects damage. AES-GCM authentication is performed on the board.
    return {'generation':generation,'vault_id':data[24:40].hex(),'size':len(data)}

def field(value:str,limit:int,*,required=False,multiline=False)->bytes:
    if not isinstance(value,str):raise VaultError('Field must be text')
    encoded=value.encode('utf-8',errors='strict')
    if len(encoded)>limit or (required and not encoded):
        raise VaultError(f'Field must contain {1 if required else 0}..{limit} UTF-8 bytes')
    if any((ord(c)<32 and not (multiline and c=='\n')) or 127<=ord(c)<=159 for c in value):
        raise VaultError('Control characters are not permitted')
    return struct.pack('<H',len(encoded))+encoded

def parse_list(data:bytes)->tuple[bytes,list[tuple[str,str]]]:
    if len(data)<34:raise VaultError('Truncated list')
    revision,count=data[:32],struct.unpack_from('<H',data,32)[0]
    if count>32:raise VaultError('Invalid record count')
    records,at=[],34
    for _ in range(count):
        if at+9>len(data):raise VaultError('Truncated record')
        rid=data[at:at+8].hex();length=data[at+8];at+=9
        if not 1<=length<=48 or at+length>len(data):raise VaultError('Invalid title size')
        title=data[at:at+length].decode('utf-8',errors='strict');field(title,48,required=True)
        records.append((rid,title));at+=length
    if at!=len(data) or len({r[0] for r in records})!=count:raise VaultError('Invalid record list')
    return revision,records

def record_id(text:str)->bytes:
    try:value=bytes.fromhex(text)
    except ValueError as e:raise VaultError('ID must be 16 hexadecimal characters') from e
    if len(text)!=16 or len(value)!=8 or value==bytes(8):raise VaultError('ID must be 16 nonzero hexadecimal characters')
    return value

class Device:
    def __init__(self,port:str):
        try:import serial
        except ImportError as e:raise VaultError('Install desktop/requirements.txt with pip') from e
        self.serial=serial.Serial(port=None,baudrate=115200,timeout=0.1,write_timeout=5)
        self.serial.dtr=False;self.serial.rts=False;self.serial.port=port;self.serial.open()
        self.buffer=bytearray();time.sleep(0.25);self.serial.reset_input_buffer()
    def close(self):self.serial.close()
    def request(self,op:int,payload:bytes=b'',timeout=15)->bytes:
        rid=secrets.randbits(32);raw=frame(op,rid,payload)
        if self.serial.write(raw)!=len(raw):raise VaultError('Partial USB write; check board state before retrying')
        self.serial.flush();until=time.monotonic()+timeout
        while time.monotonic()<until:
            self.buffer+=self.serial.read(max(1,min(4096,self.serial.in_waiting)))
            while True:
                start=self.buffer.find(b'SVC1')
                if start<0:self.buffer[:]=self.buffer[-3:];break
                if start:del self.buffer[:start]
                if len(self.buffer)<11:break
                got_op,got_id,length=struct.unpack_from('<BIH',self.buffer,4)
                if length>WIRE_MAX or not got_op&0x80:del self.buffer[0];continue
                end=15+length
                if len(self.buffer)<end:break
                packet=bytes(self.buffer[:end]);del self.buffer[:end]
                if zlib.crc32(packet[:-4])!=struct.unpack_from('<I',packet,end-4)[0]:continue
                if got_id!=rid or got_op!=(op|0x80):continue
                if not length:raise VaultError('Empty response')
                result=packet[11]
                if result:raise VaultError(RESULTS[result] if result<len(RESULTS) else f'Device error {result}')
                return packet[12:-4]
        raise VaultError('USB timeout. A completed write may have lost its reply. Check the board and refresh before retrying.')

def write_backup(path:Path,data:bytes):
    validate_backup(data);created=False
    try:
        with path.open('xb') as output:
            created=True
            if output.write(data)!=len(data):raise OSError('Partial backup write')
            output.flush();os.fsync(output.fileno())
    except BaseException:
        if created:path.unlink(missing_ok=True)
        raise

def parser():
    p=argparse.ArgumentParser(description='SoloVault: local approval, encrypted backups; no password export')
    p.add_argument('--port',help='Serial port, e.g. COM5 or /dev/ttyACM0')
    sub=p.add_subparsers(dest='command',required=True)
    for command in ('ports','status','list'):sub.add_parser(command)
    for command in ('add','edit'):
        action=sub.add_parser(command)
        if command=='edit':action.add_argument('id')
        action.add_argument('--title',required=True);action.add_argument('--user',default='');action.add_argument('--note',default='')
        group=action.add_mutually_exclusive_group()
        group.add_argument('--generate',type=int,metavar='LENGTH',help='Generate 12..64 characters on board')
        if command=='edit':group.add_argument('--keep-password',action='store_true',help='Keep password; all other fields are replaced')
    action=sub.add_parser('delete');action.add_argument('id')
    for command in ('backup','restore'):
        action=sub.add_parser(command);action.add_argument('path',type=Path)
    return p

def wait_window(command:str):
    needed='Backup' if command=='backup' else 'Restore (empty) or Manage (same vault)' if command=='restore' else 'Manage'
    input(f'On board enable USB {needed}; Manage requires local unlock. Then press Enter here: ')

def execute(args,dev:Device):
    command=args.command
    if command=='status':
        data=dev.request(OP_STATUS)
        if len(data)<7:raise VaultError('Truncated status')
        state=STATES[data[3]] if data[3]<len(STATES) else 'Unknown'
        access=ACCESS[data[5]] if data[5]<len(ACCESS) else 'Unknown'
        print(f'SoloVault {data[0]}.{data[1]}.{data[2]} | {state} | unlocked={bool(data[4])} | USB={access}')
        if data[6]:print('Old-file cleanup incomplete; check the device.')
        if len(data)>=13 and len(data)==13+data[7]:
            model=data[8:8+data[7]].decode('ascii',errors='replace')
            print(f'Chip: {model}, revision {data[8+data[7]]}, flash {struct.unpack_from("<I",data,9+data[7])[0]} bytes')
        return
    if command=='restore':
        with args.path.open('rb') as source:blob=source.read(BLOB_MAX+1)
        info=validate_backup(blob);print(f'Backup vault {info["vault_id"]}, generation {info["generation"]}.')
        input('This replaces current vault contents. Enter to continue, Ctrl+C to cancel: ')
        wait_window(command);print('Enter the BACKUP owner key on the board if asked, then hold SELECT to approve.')
        dev.request(OP_RESTORE,blob,timeout=305);print('Restored and verified. Reopen USB for another command.');return
    if command=='backup' and args.path.exists():raise VaultError('Output exists; choose a new filename')
    fields=None
    # Prepare user input before opening the short physical window.
    if command in ('add','edit'):
        title=field(args.title,48,required=True);user=field(args.user,64);note=field(args.note,160,multiline=True)
        policy,length,password=0,0,''
        if args.generate is not None:
            if not 12<=args.generate<=64:raise VaultError('--generate must be 12..64')
            policy,length=1,args.generate
        elif getattr(args,'keep_password',False):policy=2
        else:
            if not sys.stdin.isatty():raise VaultError('Password input requires an interactive terminal')
            password=getpass.getpass('Password to store (trusted computer only): ')
            if password!=getpass.getpass('Repeat password: '):raise VaultError('Passwords do not match')
        fields=bytes((policy,length))+title+user+field(password,96,required=policy==0)+note
        password='' # Python cannot guarantee erasure of immutable strings.
    wait_window(command)
    if command=='backup':
        blob=dev.request(OP_BACKUP);write_backup(args.path,blob)
        print(f'Encrypted backup saved: {args.path}. Keep the owner key separately.');return
    revision,records=parse_list(dev.request(OP_LIST))
    if command=='list':
        for rid,title in records:print(f'{rid}  {title}')
        print(f'{len(records)} record(s). Passwords are displayed only on the board.');return
    if command in ('edit','delete'):
        rid=record_id(args.id)
        if rid.hex() not in {r[0] for r in records}:raise VaultError('ID is absent from the current list')
    else:rid=bytes(8)
    print('Check action/title on board. Hold SELECT 1 second to approve; LEFT cancels.')
    if command=='delete':dev.request(OP_DELETE,revision+rid,timeout=65)
    else:
        reply=dev.request(OP_PUT,revision+rid+fields,timeout=65)
        if len(reply)!=40:raise VaultError('Unexpected reply; refresh the list')
        print('Record ID:',reply[:8].hex())
    print('Saved and verified. Reopen USB Manage for another command.')

def main(argv=None):
    args=parser().parse_args(argv);dev=None
    try:
        if args.command=='ports':
            from serial.tools import list_ports
            for port in list_ports.comports():print(f'{port.device}  {port.description}')
            return 0
        if not args.port:raise VaultError('Specify --port; use ports to list available devices')
        dev=Device(args.port);execute(args,dev);return 0
    except (VaultError,OSError,ValueError,UnicodeError) as error:
        print(f'Error: {error}',file=sys.stderr);return 1
    except (KeyboardInterrupt,EOFError):
        print('\nCancelled. Close the USB window on the board.',file=sys.stderr);return 130
    finally:
        if dev is not None:dev.close()
if __name__=='__main__':raise SystemExit(main())
