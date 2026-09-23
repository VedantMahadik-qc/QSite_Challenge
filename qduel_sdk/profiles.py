"""Versioned staged season. Constants are enforced, not attacker-provided labels.

This development release implements a measured scope, not proven monotonic hardness.
Historical profile serialization is deliberately unchanged.
"""
from __future__ import annotations
import math
import numpy as np
from .rules import Rules, CURRENT_RULESET, FRAME2_RULESET, FRAME4_RULESET, OPEN8_RULESET, EIGHT_QUBIT_RULESETS

# Keep the original plan explicitly addressable; never reinterpret an existing season.
LEGACY_LADDER_ID='progressive-frames-0.7'
LEGACY_PROFILE_IDS=(CURRENT_RULESET,FRAME2_RULESET,FRAME4_RULESET)
LADDER_ID='progressive-open-final-0.7.1'
PROFILE_IDS=(CURRENT_RULESET,FRAME2_RULESET,OPEN8_RULESET)
SEASON_PLANS={LEGACY_LADDER_ID:LEGACY_PROFILE_IDS,LADDER_ID:PROFILE_IDS}

def profile_rules(profile):
    if profile==CURRENT_RULESET:return Rules()
    if profile not in EIGHT_QUBIT_RULESETS:raise ValueError('Unknown published profile')
    return Rules(version=profile,qubits=8,total_shots=96000,checkpoints=3,
        max_settings=720,max_requests=3000,attack_max_gates=72,attack_max_entanglers=24,
        patch_max_gates=108,patch_max_entanglers=36)

def profile_info(rules):
    if rules.version==OPEN8_RULESET:
        return dict(profile_id=rules.version,qubits=8,
            title='Eight-qubit open architecture',non_clifford_insertions=None,
            structure='arbitrary_rotation_sequence',
            difficulty='Open final: no promised frame or layer structure. General recovery and competitive balance are not qualified.')
    t=2 if rules.version==FRAME2_RULESET else 4 if rules.version==FRAME4_RULESET else 0
    return dict(profile_id=rules.version,qubits=rules.qubits,
        title=('Open compact recovery' if not t else f'Eight-qubit frame / {t} non-Clifford insertions'),
        non_clifford_insertions=t,structure=('open_rotation_circuit' if not t else 'six_layers_of_8_local_then_4_matching_pair_rotations'),
        difficulty='Published structural progression; relative difficulty and load require next-pass testing')

def _range(g,t):
    if g.parameter is None:return g.low,g.high
    p=t.parameters[g.parameter]
    return tuple(sorted((g.scale*p.low+g.offset,g.scale*p.high+g.offset)))

def validate_frame_template(t,rules):
    """Prove every draw has the declared syntactic structure and angle categories.

    Does not prove effective non-Clifford rank or recovery difficulty. Complete
    circuits remain subject to the disturbance and inverse-witness admission.
    """
    if rules.version not in (FRAME2_RULESET,FRAME4_RULESET):return
    required=profile_info(rules)['non_clifford_insertions']
    if len(t.gates)!=72:raise ValueError('Frame attack requires exactly six 12-gate layers')
    noncliff=0
    for layer in range(6):
        gs=t.gates[12*layer:12*(layer+1)];local=gs[:8];pairs=gs[8:]
        if any(g.name not in ('rx','ry','rz') for g in local):raise ValueError('Each frame layer starts with eight local rotations')
        if sorted(q for g in local for q in g.targets)!=list(range(8)):raise ValueError('Each local layer touches each qubit exactly once')
        if any(g.name not in ('rxx','ryy','rzz') for g in pairs):raise ValueError('Layer ends with four pair rotations')
        if sorted(q for g in pairs for q in g.targets)!=list(range(8)):raise ValueError('Pair rotations must form a perfect matching in each layer')
        for g in gs:
            lo,hi=_range(g,t)
            quarter=abs(hi-lo)<1e-12 and abs(abs(lo)-math.pi/2)<1e-12
            if quarter:continue
            if len(g.targets)!=1:raise ValueError('Non-Clifford insertions must be local rotations')
            if not ((0.3<=lo<=hi<=0.9) or (-0.9<=lo<=hi<=-0.3)):
                raise ValueError('Insertion ranges must lie in [0.3,0.9] or [-0.9,-0.3] radians')
            noncliff+=1
    if noncliff!=required:raise ValueError(f'This round requires exactly {required} non-Clifford local insertions')

def frame_example(rules,seed=23):
    """Public template, not private runtime data. Students may edit all legal structure."""
    t=profile_info(rules)['non_clifford_insertions']
    if not t:raise ValueError('frame_example requires a frame profile; use open_example for the open final')
    rng=np.random.default_rng(seed);gates=[]
    selected=set(map(int,rng.choice(48,t,replace=False)))
    for layer in range(6):
        for q in range(8):
            sign=int(rng.choice([-1,1]));g=dict(name=str(rng.choice(['rx','ry','rz'])),targets=[q])
            if 8*layer+q in selected:
                g.update(low=0.3 if sign>0 else -0.9,high=0.9 if sign>0 else -0.3)
            else:g.update(low=sign*math.pi/2,high=sign*math.pi/2)
            gates.append(g)
        perm=rng.permutation(8)
        for j in range(0,8,2):
            ang=int(rng.choice([-1,1]))*math.pi/2
            gates.append(dict(name=str(rng.choice(['rxx','ryy','rzz'])),targets=sorted(map(int,perm[j:j+2])),low=ang,high=ang))
    return dict(name=f'Public frame {t} / {seed}',gates=gates)

def merged_frame_example(rules,seed=127,layer=2):
    """Legal frame whose two insertions sit on ONE qubit in consecutive layers.

    The pair rotation between them acts on the same axis, so the two local
    insertions commute through it and merge into a single rotation by
    2p-0.3 radians, close to a quarter turn for p near the top of the allowed
    range. Each declared insertion stays inside [0.3,0.9]; only the *effective*
    residual is nearly Clifford. A learner that trusts exact observed support
    after few shots can mistake it for a pure Clifford frame. This is a public
    practice case, not a claim about any team's defender.
    """
    t=profile_info(rules)['non_clifford_insertions']
    if not t:raise ValueError('merged_frame_example requires a frame profile')
    if not 0<=layer<5:raise ValueError('The merged pair needs two consecutive layers')
    gates=[dict(g) for g in frame_example(rules,seed)['gates']]
    pair=gates[12*layer+8];q=pair['targets'][0];axis=pair['name'][1]
    slots=(12*layer+q,12*(layer+1)+q)
    for index,offset in zip(slots,(0.0,-0.3)):
        gates[index]=dict(name='r'+axis,targets=[q],parameter='p',scale=1.0,offset=offset)
    # Keep exactly t insertions: the merged pair plus the first t-2 seeded ones.
    keep=t-2
    for index,g in enumerate(gates):
        if index in slots or g.get('parameter') is not None:continue
        if abs(g['high']-g['low'])>1e-12:
            if keep>0:keep-=1;continue
            sign=1 if g['low']>0 else -1;g['low']=g['high']=sign*math.pi/2
    return dict(name=f'Merged same-qubit insertions near a quarter turn / {seed}',
                parameters={'p':{'low':0.85,'high':0.9}},gates=gates)

def practice_bank(rules):
    from .examples import PUBLIC_PRACTICE_4Q
    if rules.qubits==4:return PUBLIC_PRACTICE_4Q
    if rules.version==OPEN8_RULESET:return open_practice_bank(rules)
    bank={key:frame_example(rules,seed) for key,seed in [('local',23),('zz',29),('mixed',31),('frame',37)]}
    bank['merged']=merged_frame_example(rules,127)
    return bank


def open_example(rules,seed=23,*,gates=36,entanglers=12):
    """Return one editable public architecture, not a requirement or difficulty claim.

    This helper chooses an architecture ONCE. The submitted template retains it;
    its declared angles are independently sampled in each realization. The server
    does not secretly rerandomize the submitted gate sequence.
    """
    if rules.version!=OPEN8_RULESET:raise ValueError('open_example requires the open final profile')
    if type(gates) is not int or type(entanglers) is not int:
        raise ValueError('Gate counts must be integers')
    if not 1<=gates<=rules.attack_max_gates or not 0<=entanglers<=min(gates,rules.attack_max_entanglers):
        raise ValueError('Requested example exceeds the attack budget')
    rng=np.random.default_rng(seed)
    pair_slots=set(map(int,rng.choice(gates,entanglers,replace=False)))
    instructions=[]
    for i in range(gates):
        arity=2 if i in pair_slots else 1
        axis=str(rng.choice(['x','y','z']))
        targets=sorted(map(int,rng.choice(rules.qubits,arity,replace=False)))
        center=float(rng.uniform(0.5,2.0))*int(rng.choice([-1,1]))
        instructions.append(dict(name='r'+axis*arity,targets=targets,
                                 low=center-0.15,high=center+0.15))
    return dict(name=f'Public open circuit / {seed}',gates=instructions)


def open_practice_bank(rules):
    """Simple regression cases plus broader design examples; never an attack whitelist."""
    if rules.version!=OPEN8_RULESET:raise ValueError('Wrong practice profile')
    return {
        'local':dict(name='Open warm-up: q0 phase',gates=[
            dict(name='rz',targets=[0],low=0.9,high=1.2)]),
        'zz':dict(name='Open warm-up: q0-q1 coupling',gates=[
            dict(name='rzz',targets=[0,1],low=-1.2,high=-0.9)]),
        'mixed':open_example(rules,31,gates=18,entanglers=6),
        'multilayer':open_multilayer_example(rules,37),
        'frame':frame_example(profile_rules(FRAME4_RULESET),41),
    }


def open_multilayer_example(rules,seed=37):
    """One ordinary continuous-angle six-layer example; layers are NOT required."""
    if rules.version!=OPEN8_RULESET:raise ValueError('Wrong practice profile')
    example=frame_example(profile_rules(FRAME2_RULESET),seed)
    example['name']=f'Public continuous multilayer / {seed}'
    rng=np.random.default_rng(seed+10000)
    for gate in example['gates']:
        center=float(rng.uniform(.5,2.0))*int(rng.choice([-1,1]))
        gate['low'],gate['high']=center-.15,center+.15
    return example
