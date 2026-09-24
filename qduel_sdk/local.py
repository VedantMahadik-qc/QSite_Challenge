"""Offline, trusted-code laboratory with the official public oracle contract.

Not a security boundary: the local organizer/owner knows the generated circuit.
No network, database, account or competition score is involved. The solver-facing
client returns counts only. Scores are available from the session after sealing.
"""
from __future__ import annotations
import copy, json
from dataclasses import dataclass
from pathlib import Path
import numpy as np
from duelkit.quantum import (G, from_data, circuit_data, validate, unitary, infidelity,
    independent_unitary, probabilities, experiment_at, experiment_index, bitstrings,
    expectation_from_counts, wilson_expectation)
from .rules import Rules
from .contracts import Query, QueryBatch, Patch, Action
from .serialization import digest

@dataclass
class LocalSession:
    attack: tuple
    rules: Rules
    seed: int = 123

    def __post_init__(self):
        validate(self.attack, **self.rules.validation_kwargs('attack'))
        self._u = unitary(self.attack, self.rules.qubits)
        self._rng = np.random.default_rng(self.seed)
        self._stage = self._spent = self._forfeited = self._requests = self._patches = 0
        self._patch = (); self._settings = set(); self._receipts = {}; self._serial = 0
        self.records = []; self.checkpoints = []

    def client(self):
        return LocalClient(self)

    def status(self):
        r=self.rules
        return dict(checkpoint=min(self._stage+1,r.checkpoints),
            state='FINISHED' if self._stage>=r.checkpoints else 'MEASURING',
            spent_shots=self._spent,forfeited_shots=self._forfeited,total_budget=r.total_shots,
            available_now=0 if self._stage>=r.checkpoints else (self._stage+1)*r.block-self._spent-self._forfeited,
            distinct_settings=len(self._settings),requests=self._requests,qubits=r.qubits,
            ruleset=r.version,rules=r.model_dump())

    def _cached(self,kind,body):
        key=body.request_id;h=digest({'kind':kind,'payload':body.model_dump()})
        if key in self._receipts:
            old_hash, result=self._receipts[key]
            if old_hash!=h: raise ValueError('Idempotency key reused with different contents')
            return h,copy.deepcopy(result)
        return h,None

    def _mutable(self):
        if self._stage>=self.rules.checkpoints: raise ValueError('Encounter is sealed')
        if self._requests>=self.rules.max_requests: raise ValueError('Encounter action limit reached')

    def _save(self,kind,body,h,result):
        result=copy.deepcopy(result);self._receipts[body.request_id]=(h,result);self._requests+=1
        self.records.append(dict(kind=kind,payload=copy.deepcopy(result)))
        return copy.deepcopy(result)

    def query(self,index,shots,request_id,analysis_patch=()):
        b=Query(request_id=request_id,experiment_index=index,shots=shots,
                analysis_patch=circuit_data(analysis_patch))
        h,old=self._cached('measurement',b)
        if old is not None:return old
        self._mutable();r=self.rules
        c=tuple(x.gate_record() for x in b.analysis_patch)
        validate(c,**r.validation_kwargs())
        if b.shots>self.status()['available_now']:raise ValueError('Request crosses checkpoint; close it explicitly first')
        if b.experiment_index>=r.experiment_count:raise ValueError('Experiment index outside this round')
        key=digest([b.experiment_index,circuit_data(c)])
        if key not in self._settings and len(self._settings)>=r.max_settings:raise ValueError('Distinct-setting budget exhausted')
        p=probabilities(unitary(c,r.qubits)@self._u,[index])[0]
        counts=self._rng.multinomial(shots,p)
        self._spent+=shots;self._settings.add(key)
        result=dict(request_id=request_id,experiment_index=index,shots=shots,analysis_patch=circuit_data(c),
            **experiment_at(index,r.qubits).data(),counts={b:int(v) for b,v in zip(bitstrings(r.qubits),counts)},
            spent_shots=self._spent,checkpoint=self._stage+1)
        return self._save('measurement',b,h,result)

    def query_batch(self,experiments):
        batch=QueryBatch(experiments=experiments)
        # Snapshot public local bookkeeping. The process is trusted, not a sandbox.
        snapshot=copy.deepcopy({k:v for k,v in self.__dict__.items() if k!='_u'})
        try:
            return [self.query(q.experiment_index,q.shots,q.request_id,tuple(g.gate_record() for g in q.analysis_patch)) for q in batch.experiments]
        except BaseException:
            u=self._u;self.__dict__.clear();self.__dict__.update(snapshot);self._u=u;raise

    def patch(self,patch,request_id,note=''):
        b=Patch(request_id=request_id,patch=circuit_data(patch),note=note)
        h,old=self._cached('patch',b)
        if old is not None:return old
        self._mutable();c=tuple(x.gate_record() for x in b.patch)
        costs=validate(c,**self.rules.validation_kwargs())
        if self._patches>=60:raise ValueError('Patch update cap reached')
        self._patch=c;self._patches+=1
        return self._save('patch',b,h,dict(accepted=True,patch_hash=digest(circuit_data(c)),patch=circuit_data(c),
                    note=note,resources=costs,checkpoint=self._stage+1))

    def _checkpoint(self):
        r=self.rules
        self._forfeited+=(self._stage+1)*r.block-self._spent-self._forfeited
        self._stage+=1
        cp=dict(stage=self._stage,spent_shots=self._spent,forfeited_shots=self._forfeited,
                patch=circuit_data(self._patch),patch_hash=digest(circuit_data(self._patch)))
        self.checkpoints.append(copy.deepcopy(cp));self.records.append(dict(kind='checkpoint',payload=cp))

    def close_checkpoint(self,request_id):
        b=Action(request_id=request_id);h,old=self._cached('close',b)
        if old is not None:return old
        self._mutable();self._checkpoint()
        return self._save('close',b,h,self.status())

    def finish(self,request_id):
        b=Action(request_id=request_id);h,old=self._cached('finish',b)
        if old is not None:return old
        if self._stage>=self.rules.checkpoints:return self.status()
        while self._stage<self.rules.checkpoints:self._checkpoint()
        return self._save('finish',b,h,self.status())

    def result(self):
        if self._stage<self.rules.checkpoints:raise ValueError('Scores withheld: finish the local encounter first')
        scores=[];r=self.rules
        for cp in self.checkpoints:
            err=infidelity(unitary(from_data(cp['patch']),r.qubits)@self._u)
            independent=infidelity(independent_unitary(from_data(cp['patch']),r.qubits)@independent_unitary(self.attack,r.qubits))
            if abs(err-independent)>1e-10:raise ValueError('Independent score disagreement')
            q=100.0 if err<=r.good_error else 0.0 if err>=r.bad_error else 100*np.log(r.bad_error/err)/np.log(r.bad_error/r.good_error)
            scores.append({**cp,'process_infidelity':err,'recovery_points':float(q)})
        return dict(mode='LOCAL_PRACTICE_NOT_OFFICIAL',rules=r.model_dump(),
                    spent_shots=self._spent,distinct_settings=len(self._settings),requests=self._requests,
                    checkpoint_scores=scores,recovery_points=float(np.mean([c['recovery_points'] for c in scores])),
                    records=copy.deepcopy(self.records))

class LocalClient:
    """Duck-typed equivalent of OracleClient; no method returns the hidden attack or score."""
    def __init__(self,session):self._session=session;self.counter=0
    def _id(self,kind):self.counter+=1;return f'{kind}-local-{self.counter}'
    def query_batch(self,experiments):return self._session.query_batch(experiments)
    def status(self):return self._session.status()
    def query(self,index,shots,request_id,analysis_patch=()):return self._session.query(index,shots,request_id,analysis_patch)
    def query_experiment(self,prep,basis,shots,request_id,analysis_patch=()):
        return self.query(experiment_index(prep,basis,self._session.rules.qubits),shots,request_id,analysis_patch)
    def submit_patch(self,patch,note=''):return self._session.patch(patch,self._id('patch'),note)
    def close_checkpoint(self):return self._session.close_checkpoint(self._id('close'))
    def finish(self):return self._session.finish(self._id('finish'))
    def close(self):pass


def measured_residuals(receipt):
    """Compatible observables vs identity, from a single recorded physical experiment.

    Analysis is part of the executed process C A; identity remains the desired
    combined output. This is not a reconstruction of the unanalysed attack.
    """
    n=len(receipt['basis']);result=[]
    for mask in range(1,1<<n):
        label='';target=1.0
        for j,(prep,axis) in enumerate(zip(receipt['prep'],receipt['basis'])):
            if mask & (1<<(n-1-j)):
                label+=axis;target*= (1 if prep[1]=='+' else -1) if prep[0]==axis else 0
            else:label+='I'
        mean=expectation_from_counts(receipt['counts'],mask)
        low,high=wilson_expectation(receipt['counts'],mask)
        result.append(dict(pauli=label,observed=mean,target=target,residual=mean-target,
                           interval_low=low-target,interval_high=high-target))
    return result
