"""Offline inspection of a team's released competition record (no hidden source)."""
from .serialization import digest
from .local import measured_residuals

def verify_replay(replay):
    head='0'*64;eid=replay['encounter_id']
    for index,row in enumerate(replay['records']):
        body={k:row[k] for k in ('encounter_id','sequence','kind','payload','previous')}
        if row['encounter_id']!=eid or row['sequence']!=index or row['previous']!=head or digest(body)!=row['hash']:
            raise ValueError(f'Replay chain mismatch at record {index}')
        head=row['hash']
    if head!=replay['audit_head']:raise ValueError('Replay head mismatch')
    return {'chain_consistent':True,'records':len(replay['records']),
      'note':'Integrity against the provided head, not an independent signature or hidden-process re-evaluation.'}

def measurements(replay):
    return [r['payload'] for r in replay['records'] if r['kind']=='measurement']
