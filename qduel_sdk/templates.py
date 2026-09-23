"""Data-only attack grammar. Shared parameters enable coordinated cancellations.

The distribution is uniform independent parameter draws conditioned on the
published minimum disturbance. No defender's performance participates in admission.
"""
import numpy as np
from .contracts import Template
from qduel_sdk.rules import Rules, LEGACY_RULESET
from duelkit.quantum import G,validate,unitary,inverse,infidelity,global_distance,independent_unitary
from .serialization import digest

ADMISSION_DRAWS=64
ADMISSION_MIN_QUALIFYING=32


class SamplingExhausted(ValueError):
    """A bounded rejection-sampling batch found no qualifying realization."""


def draw(t:Template,rng):
    params={name:float(rng.uniform(p.low,p.high)) for name,p in t.parameters.items()}
    result=[]
    for g in t.gates:
        if g.parameter is not None:angle=g.scale*params[g.parameter]+g.offset
        elif g.low is not None:angle=float(rng.uniform(g.low,g.high))
        else:angle=None
        result.append(G(g.name,tuple(g.targets),angle))
    return tuple(result)

def validate_template(t,rules):
    from .profiles import validate_frame_template
    validate_frame_template(t,rules)
    if len(t.parameters)>rules.attack_max_gates:raise ValueError('Too many parameters for this round')
    if rules.version==LEGACY_RULESET and t.parameters:
        raise ValueError('Named angle parameters require the four-qubit ruleset')
    # Check at midpoint; interval checks were made by Template, never eval() strings.
    class Midpoint:
        def uniform(self,lo,hi):return (lo+hi)/2
    validate(draw(t,Midpoint()),**rules.validation_kwargs('attack'))

def instantiate(t:Template,seed:int,rules:Rules,attempts:int=256):
    validate_template(t,rules)
    rng=np.random.default_rng(seed)
    for attempt in range(attempts):
        circuit=draw(t,rng)
        validate(circuit,**rules.validation_kwargs('attack'))
        u=unitary(circuit,rules.qubits)
        # Legacy tolerance is retained only for historical manifests.
        tol=1e-12 if rules.version==LEGACY_RULESET else 0
        if infidelity(u)+tol<rules.min_attack_error:continue
        patch=inverse(circuit)
        validate(patch,**rules.validation_kwargs('patch'))
        if (infidelity(unitary(patch,rules.qubits),u.conj().T) if rules.qubits==8 else infidelity(unitary(patch,rules.qubits)@u))>1e-10:
            raise ValueError('Inverse witness did not verify')
        if np.max(np.abs(independent_unitary(circuit,rules.qubits)-u))>1e-10:
            raise ValueError('Independent attack matrix mismatch')
        return circuit
    raise SamplingExhausted(f'No qualifying draw after {attempts} attempts; revise template ranges')


def sampling_readiness(t,rules):
    """Screen unconditional draws, rather than counting eventual retry successes.

    This reproducible screen is deliberately not a proof of a template's acceptance
    probability. In particular, public screening seeds are not secret randomness.
    Scheduling also uses bounded, independent private-seed retry batches.
    """
    rng=np.random.default_rng(20260920)
    tolerance=1e-12 if rules.version==LEGACY_RULESET else 0
    accepted=sum(infidelity(unitary(draw(t,rng),rules.qubits))+tolerance>=rules.min_attack_error
                 for _ in range(ADMISSION_DRAWS))
    if accepted<ADMISSION_MIN_QUALIFYING:
        raise ValueError(f'Attack template {t.name!r} qualifies on only {accepted}/{ADMISSION_DRAWS} '
                         f'unconditional admission draws; at least {ADMISSION_MIN_QUALIFYING} are required. '
                         'Narrow or revise the angle ranges so qualifying attacks are reliable.')
    return {'qualifying':int(accepted),'draws':ADMISSION_DRAWS,'minimum':ADMISSION_MIN_QUALIFYING}

def semantic_template_key(t,rules):
    """Conservative exact-Pauli simplification, not arbitrary unitary equivalence.

    Cancel/merge rotations through commuting generators; remove zero wrappers;
    normalize parameter names and uniform-range centers. The unchanged gate caps
    still apply to the submitted circuit, not this diagnostic representation.
    """
    if rules.version==LEGACY_RULESET:return None
    ranges={k:((p.low+p.high)/2,(p.high-p.low)/2) for k,p in t.parameters.items()}
    ops=[]
    def commute(a,b):return sum(x!='I' and y!='I' and x!=y for x,y in zip(a,b))%2==0
    for i,g in enumerate(t.gates):
        axis=g.name[-1].upper();label=''.join(axis if q in g.targets else 'I' for q in range(rules.qubits))
        if g.parameter is None:
            mid=(g.low+g.high)/2;rad=(g.high-g.low)/2;key=f'free-{i}'
            ranges[key]=(mid,rad);constant=mid;coeff={key:1.0} if rad else {}
        else:
            mid,rad=ranges[g.parameter];constant=g.offset+g.scale*mid;coeff={g.parameter:g.scale} if rad else {}
        for j in range(len(ops)-1,-1,-1):
            old,base,terms=ops[j]
            if old==label:
                constant+=base
                for k,v in terms.items():coeff[k]=coeff.get(k,0)+v
                ops.pop(j);break
            if not commute(old,label):break
        coeff={k:v for k,v in coeff.items() if abs(v)>1e-13}
        constant=(constant+np.pi)%(2*np.pi)-np.pi
        if coeff or abs(constant)>1e-12:ops.append((label,constant,coeff))
    names={};normalized=[]
    for label,const,terms in ops:
        transformed=[]
        for k,v in sorted(terms.items(),key=lambda kv:(ranges[kv[0]][1],abs(kv[1]),kv[0])):
            if k not in names:names[k]=(len(names),1 if v>0 else -1)
            idx,sign=names[k];transformed.append((idx,round(v*sign*ranges[k][1],12)))
        normalized.append((label,round(const,12),sorted(transformed)))
    return digest(normalized)

def qualify(templates:list[Template],rules:Rules,*,check_sampling=True):
    fingerprints=[digest({'parameters':{k:v.model_dump() for k,v in t.parameters.items()},
        'gates':[g.model_dump() for g in t.gates]}) for t in templates]
    if len(fingerprints)!=2 or len(set(fingerprints))!=2:
        raise ValueError('Supply two distinct attack templates')
    for t in templates:validate_template(t,rules)
    semantic=[semantic_template_key(t,rules) for t in templates]
    if semantic[0] is not None and semantic[0]==semantic[1]:
        raise ValueError('Attack templates reduce to the same parameterized Pauli process')
    readiness=[sampling_readiness(t,rules) for t in templates] if check_sampling else []
    constant=all(p.low==p.high for t in templates for p in t.parameters.values()) and all(
        g.low==g.high for t in templates for g in t.gates if g.low is not None)
    equivalent_draws=0
    for seed in range(8):
        cs=[instantiate(t,1009+seed,rules) for t in templates]
        if global_distance(unitary(cs[0],rules.qubits),unitary(cs[1],rules.qubits))<1e-7:
            equivalent_draws+=1
            if constant:raise ValueError('Attack circuits are equivalent up to global phase')
    if equivalent_draws==8:raise ValueError('Attack templates are equivalent on every validation draw; submit distinct processes')
    return {'status':'VALIDATED','readiness_draws':16,'sampling_readiness':readiness,
      'family_distinctness':'Pauli cancellation/parameter normalization plus eight paired semantic draws; not a general family inequivalence proof',
      'sampling':'independent parameter draws conditioned on minimum error; max 256 attempts',
      'native_cost':'NOT_VERIFIED','qubits':rules.qubits,'ruleset':rules.version}
