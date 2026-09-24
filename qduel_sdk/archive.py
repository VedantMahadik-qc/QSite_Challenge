"""Bounded, nonexecuting ZIP validation shared by upload and runner extraction."""
from __future__ import annotations
import ast
import hashlib
import io
import json
import pathlib
import stat
import zipfile

MAX_ARCHIVE=2_000_000
MAX_EXPANDED=4_000_000
MAX_MEMBERS=64
SUFFIXES={'.py','.json','.md','.txt'}
RESERVED={'qduel','qduel_runner','duelkit','qduel_sdk'}


def inspect_archive(blob:bytes)->dict:
    if not blob or len(blob)>MAX_ARCHIVE:
        raise ValueError('Archive limit is 2 MB')
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            members=z.infolist()
            if len(members)>MAX_MEMBERS:
                raise ValueError('At most 64 archive members are allowed')
            total=0;seen=set();files=set();directories=set();manifest=[];contents={}
            for item in members:
                name=item.filename
                # ZipInfo truncates filename at NUL, but preserves orig_filename.
                if '\x00' in item.orig_filename or '\\' in name or name.startswith('/'):
                    raise ValueError('Unsafe archive path')
                p=pathlib.PurePosixPath(name)
                if (not p.parts or any(v in {'..','.'} for v in p.parts)
                    or ':' in name or any(ord(c)<32 for c in name)
                    or str(p)!=name.rstrip('/') or len(name)>160):
                    raise ValueError('Noncanonical archive path')
                canonical=str(p).casefold()
                if canonical in seen:raise ValueError('Duplicate archive member')
                seen.add(canonical)
                ancestors={str(a).casefold() for a in p.parents if str(a)!='.'}
                if ancestors & files or canonical in files or (not item.is_dir() and canonical in directories):
                    raise ValueError('Archive file/directory path collision')
                mode=item.external_attr>>16
                if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR):
                    raise ValueError('Symlinks and special files are prohibited')
                if item.flag_bits&1:raise ValueError('Encrypted archives are prohibited')
                root=pathlib.PurePosixPath(p.parts[0])
                if root.name.casefold() in RESERVED or (root.suffix.casefold()=='.py' and root.stem.casefold() in RESERVED):
                    raise ValueError('Reserved platform package names cannot be uploaded')
                directories.update(ancestors)
                if item.is_dir():
                    directories.add(canonical)
                    continue
                if p.suffix not in SUFFIXES:
                    raise ValueError('Only participant Python/data files are allowed')
                if item.file_size>1_000_000 or item.file_size>max(1024,item.compress_size*200):
                    raise ValueError('Archive member or compression ratio exceeds limit')
                total+=item.file_size
                if total>MAX_EXPANDED:raise ValueError('Expanded archive limit is 4 MB')
                data=z.read(item)
                if len(data)!=item.file_size:raise ValueError('Archive size mismatch')
                if p.suffix=='.py':
                    try:
                        source=data.decode('utf-8')
                        tree=ast.parse(source,filename=name)
                        compile(tree,name,'exec')  # compilation is nonexecuting; rejects return/break outside legal scopes
                    except UnicodeDecodeError:
                        raise ValueError('Python sources must be UTF-8') from None
                    except (SyntaxError,ValueError,RecursionError) as exc:
                        line=getattr(exc,'lineno',None)
                        raise ValueError(f'Invalid Python syntax in {name}'+(f' at line {line}' if line else '')) from None
                files.add(canonical);contents[name]=data
                manifest.append({'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
            if 'main.py' not in contents:
                raise ValueError('Archive root must contain the exact file main.py with run(client, rules)')
            protocol=None
            if 'qduel.json' in seen:
                if 'qduel.json' not in contents:raise ValueError('Protocol must be the exact file qduel.json')
                try:protocol=json.loads(contents['qduel.json'])
                except (ValueError,UnicodeDecodeError,RecursionError):raise ValueError('Invalid qduel.json') from None
                if (not isinstance(protocol,dict) or type(protocol.get('qubits')) is not int
                    or protocol['qubits'] not in (2,4,8) or not isinstance(protocol.get('protocols'),list)
                    or not protocol['protocols'] or any(not isinstance(x,str) or not x for x in protocol['protocols'])):
                    raise ValueError('Invalid optional protocol declaration')
    except (zipfile.BadZipFile,NotImplementedError,RuntimeError,EOFError) as exc:
        raise ValueError('A readable, unencrypted ZIP with valid checksums is required') from exc
    return {'protocol':protocol,'sha256':hashlib.sha256(blob).hexdigest(),'bytes':len(blob),
        'expanded_bytes':total,'files':manifest,'validation':'archive and syntax checks only; not executed'}


def safe_extract(blob:bytes,root:pathlib.Path):
    import os
    inspect_archive(blob)
    root.mkdir(parents=True,exist_ok=True)
    if any(root.iterdir()):raise ValueError('Extraction directory must be empty')
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for item in z.infolist():
            p=root/pathlib.PurePosixPath(item.filename)
            if item.is_dir():p.mkdir(parents=True,exist_ok=True);continue
            p.parent.mkdir(parents=True,exist_ok=True)
            fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:f.write(z.read(item))
