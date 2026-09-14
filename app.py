from pathlib import Path
from collections import Counter
import hashlib
import math
import mimetypes
import os
import re
import struct
import sys
from runtime import entry,parser,powershell

def inspect(path,strings=False):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ValueError('Wymagany zwykły plik.')
    before=path.stat();counts=Counter();sample=b''
    hashes={a:hashlib.new(a) for a in ('sha256','sha512','sha1','md5')}
    with path.open('rb') as f:
        head=f.read(64);f.seek(0)
        for block in iter(lambda:f.read(1024*1024),b''):
            counts.update(block)
            for h in hashes.values():h.update(block)
            if strings and len(sample)<1024*1024:sample+=block[:1024*1024-len(sample)]
        pe=None
        if head.startswith(b'MZ') and len(head)>=64:
            offset=struct.unpack_from('<I',head,60)[0]
            if offset<=before.st_size-24:
                f.seek(offset);header=f.read(24)
                if header[:4]==b'PE\0\0':
                    machine,sections,timestamp=struct.unpack_from('<HHI',header,4)
                    pe=dict(machine=hex(machine),sections=sections,timestamp=timestamp)
    after=path.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('Plik zmienił się podczas analizy.')
    magic='unknown'
    for prefix,mime in [(b'\x89PNG\r\n\x1a\n','image/png'),(b'%PDF-','application/pdf'),(b'PK\x03\x04','application/zip'),(b'MZ','application/vnd.microsoft.portable-executable')]:
        if head.startswith(prefix):magic=mime;break
    entropy=-sum((n/before.st_size)*math.log2(n/before.st_size) for n in counts.values()) if before.st_size else 0
    signature={'status':'UNAVAILABLE'}
    if os.name=='nt':
        escaped=str(path.resolve()).replace("'","''")
        try:signature=powershell(f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped}';[pscustomobject]@{{status=[string]$s.Status;publisher=$s.SignerCertificate.Subject}} | ConvertTo-Json")
        except (OSError,RuntimeError,ValueError):pass
    return dict(path=str(path.resolve()),name=path.name,extension=path.suffix,mime_by_extension=mimetypes.guess_type(path.name)[0],mime_by_magic=magic,
       size=before.st_size,modified_timestamp=before.st_mtime,created_timestamp=getattr(before,'st_birthtime',before.st_ctime if os.name=='nt' else None),
       hashes={a:h.hexdigest() for a,h in hashes.items()},entropy_bits_per_byte=entropy,signature=signature,pe=pe,
       strings=[s.decode('ascii') for s in re.findall(rb'[\x20-\x7e]{6,}',sample)[:100]] if strings else [],strings_sampled_bytes=len(sample),
       note='SHA1/MD5 wyłącznie dla kompatybilności. Entropia i brak podpisu nie dowodzą malware.')

def build():
    p=parser('Inspekcja pliku bez wykonania.')
    p.add_argument('file',nargs='?')
    p.add_argument('--strings',action='store_true',help='Dołącz do raportu ciągi znaków; mogą zawierać prywatne dane')
    return p

def handle(args):
    if not args.file:raise ValueError('Podaj plik.')
    return inspect(args.file,args.strings)

if __name__=='__main__':sys.exit(entry(build,handle))
