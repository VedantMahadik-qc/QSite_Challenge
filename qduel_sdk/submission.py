"""One-file competition entry; the same nonexecuting checks run online and offline.

Never execute submitted code on the web server. Local smoke tests are an explicit,
trusted-code action and do not certify security or correctness on unseen attacks.
"""
from __future__ import annotations
import ast, hashlib, inspect, io, json, os, subprocess, sys, tempfile, zipfile
from pathlib import Path
from typing import Any
from pydantic import Field
from .contracts import Strict, Template
from .rules import Rules, CURRENT_RULESET, EIGHT_QUBIT_RULESETS
from .archive import inspect_archive, safe_extract
from .serialization import digest
from .templates import qualify

FORMAT='quantum-duel-submission-v1'
class SubmissionMetadata(Strict):
    format: str
    version: str = Field(min_length=1,max_length=40,pattern=r'^[\w. -]+$')
    rules: Rules
    rules_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    attacks_file: str = 'attacks.json'
    entrypoint: str = 'main.py'


def _json(data):
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ValueError('Duplicate JSON key in submission metadata')
            out[k]=v
        return out
    try:return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite JSON number')))
    except (UnicodeDecodeError,RecursionError):raise ValueError('Invalid or excessively nested submission JSON') from None


def validate_submission_archive(blob: bytes, rules: Rules | None = None, *, check_sampling: bool = True) -> dict:
    """Validate archive, explicit run signature, rules hash and both attack templates.

    No imports/execution of participant code. A local report is never trusted as
    evidence by the server; this function recomputes checks from the uploaded bytes.
    Only integrity checks on already admitted immutable entries may opt out of
    the current sampling-readiness screen; new admissions use the default.
    """
    archive=inspect_archive(blob)
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        required={'submission.json','attacks.json','qduel.json','main.py'}
        if not required.issubset(z.namelist()):
            raise ValueError('Upload the complete ZIP exported by the student notebook (submission.json, attacks.json, qduel.json, main.py)')
        meta=SubmissionMetadata.model_validate(_json(z.read('submission.json')))
        if meta.format!=FORMAT or meta.attacks_file!='attacks.json' or meta.entrypoint!='main.py':
            raise ValueError('Unsupported submission format or entrypoint')
        if meta.rules_sha256!=digest(meta.rules.model_dump()):raise ValueError('Submission rules checksum mismatch')
        effective=rules or meta.rules
        if effective.version not in (CURRENT_RULESET, *EIGHT_QUBIT_RULESETS):raise ValueError('Use the historical submission API for legacy rounds')
        if meta.rules.model_dump()!=effective.model_dump():
            raise ValueError('Notebook rules differ from this round. Download the notebook for the selected round, then revalidate and export.')
        declaration=_json(z.read('qduel.json'))
        if not declaration or declaration['qubits']!=effective.qubits or effective.version not in declaration['protocols']:
            raise ValueError('qduel.json must declare the selected round protocol and qubit count')
        tree=ast.parse(z.read('main.py').decode('utf-8'),filename='main.py')
        functions=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=='run']
        if len(functions)!=1 or isinstance(functions[0],ast.AsyncFunctionDef):
            raise ValueError('main.py must define one top-level synchronous run(client, rules) function')
        node=functions[0];params=node.args.posonlyargs+node.args.args
        # Require an explicit, simple supported ABI. No decorated or generator entrypoint.
        if (len(params)!=2 or node.args.vararg or node.args.kwarg or node.args.kwonlyargs
                or node.decorator_list or any(isinstance(n,(ast.Yield,ast.YieldFrom)) for n in ast.walk(node))):
            raise ValueError('Use an undecorated, nongenerator run(client, rules) with exactly two positional arguments')
        raw=_json(z.read('attacks.json'))
        if not isinstance(raw,list) or len(raw)!=2:raise ValueError('attacks.json must contain exactly two attack templates')
        attacks=[Template.model_validate(t) for t in raw]
        attack_check=qualify(attacks,effective,check_sampling=check_sampling)
    return dict(status='STATIC_VALIDATED',format=FORMAT,version=meta.version,sha256=archive['sha256'],
                rules=effective.model_dump(),rules_sha256=meta.rules_sha256,
                archive=archive,attacks=[t.model_dump() for t in attacks],attack_check=attack_check,
                code_execution='NOT_RUN',warning='Static validity is not proof of runtime success, unseen-attack recovery or security.')


def build_submission(source_dir, attacks, output, *, version='v1', rules=None, files=('main.py',)) -> Path:
    """Package only an explicit allowlist; never ZIP a notebook or project directory wholesale."""
    rules=rules or Rules();source_dir=Path(source_dir).resolve();output=Path(output).resolve()
    if len(set(files))!=len(files):raise ValueError('Duplicate source paths')
    reserved={'qduel.json','attacks.json','submission.json'}
    content={}
    for name in files:
        p=source_dir/name
        if p.is_symlink() or not p.resolve().is_relative_to(source_dir):raise ValueError('Source paths must stay in the solution directory and not be symlinks')
        if name in reserved:raise ValueError('Metadata is generated by the packager, not copied from source files')
        content[name]=p.read_bytes()
    parsed=[t if isinstance(t,Template) else Template.model_validate(t) for t in attacks]
    content['attacks.json']=json.dumps([t.model_dump() for t in parsed],indent=2,allow_nan=False).encode()
    content['qduel.json']=json.dumps({'qubits':rules.qubits,'protocols':[rules.version]}).encode()
    content['submission.json']=json.dumps(dict(format=FORMAT,version=version,rules=rules.model_dump(),
                rules_sha256=digest(rules.model_dump()),attacks_file='attacks.json',entrypoint='main.py'),indent=2).encode()
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
        for name,data in sorted(content.items()):
            # Reproducible bytes: no changing filesystem timestamps.
            info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100600<<16;z.writestr(info,data)
    blob=buf.getvalue();validate_submission_archive(blob,rules)
    output.parent.mkdir(parents=True,exist_ok=True)
    temporary=output.with_name(output.name+'.tmp');temporary.write_bytes(blob);os.replace(temporary,output)
    return output


def smoke_submission(archive_path, *, rules=None, cases=('local','zz'), seeds=(41,),
                     trusted_code=False, timeout=180):
    """Execute YOUR code only, in fresh local processes. No hostile-code sandbox.

    A finite timeout terminates the subprocess, not every possible malicious child.
    Network access and filesystem containment are not guaranteed. Never pass an
    untrusted opponent archive or run this on the competition server.
    """
    if not trusted_code:raise ValueError('Local smoke tests execute Python. Set trusted_code=True only for code you trust.')
    path=Path(archive_path).resolve();checked=validate_submission_archive(path.read_bytes(),rules)
    results=[]
    with tempfile.TemporaryDirectory(prefix='qduel-local-') as tmp:
        tmp=Path(tmp);source=tmp/'submission';safe_extract(path.read_bytes(),source)
        for i,(case,seed) in enumerate((c,s) for c in cases for s in seeds):
            spec=tmp/f'case-{i}.json';result=tmp/f'result-{i}.json';log=tmp/f'log-{i}.txt'
            spec.write_text(json.dumps(dict(source=str(source),rules=checked['rules'],case=case,seed=int(seed),result=str(result))))
            env={**os.environ,'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1','PYTHONDONTWRITEBYTECODE':'1',
                 'PYTHONPATH':str(Path(__file__).resolve().parents[1])}
            with log.open('wb') as stream:
                try:
                    run=subprocess.run([sys.executable,'-m','qduel_sdk.smoke_worker',str(spec)],
                        cwd=tmp,env=env,stdout=stream,stderr=stream,timeout=timeout,check=False)
                    if result.exists():row=json.loads(result.read_text())
                    else:row={'status':'FAILED','error':'Defender exited without a result','returncode':run.returncode}
                except subprocess.TimeoutExpired:
                    row={'status':'FAILED','error':'Local smoke timeout exceeded'}
            row.update(case=case,seed=int(seed));results.append(row)
    return {'status':'PASSED' if results and all(x['status']=='PASSED' for x in results) else 'FAILED',
            'cases':results,'security':'TRUSTED_LOCAL_ONLY_NOT_SANDBOXED',
            'scope':'No hidden competition instances, hosting, or external service used.'}


def validate_solution(archive_path, *, rules=None, run_smoke=False, trusted_code=False,
                      cases=('local','zz'), seeds=(41,), timeout=180):
    """Student-facing preflight. Recomputed by the server; never trust a supplied report."""
    try:
        result=validate_submission_archive(Path(archive_path).read_bytes(),rules)
    except (ValueError,OSError) as exc:
        return {'status':'INVALID','valid_for_upload':False,'errors':[str(exc)],'code_execution':'NOT_RUN'}
    result['valid_for_upload']=True
    if run_smoke:
        smoke=smoke_submission(archive_path,rules=rules,cases=cases,seeds=seeds,trusted_code=trusted_code,timeout=timeout)
        result['smoke']=smoke;result['code_execution']='EXECUTED_TRUSTED_LOCAL'
        result['status']='VALIDATED_LOCALLY' if smoke['status']=='PASSED' else 'RUNTIME_FAILED'
        result['valid_for_upload']=smoke['status']=='PASSED'
    return result
