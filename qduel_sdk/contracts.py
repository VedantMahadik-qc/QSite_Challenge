"""Public data-only submission/oracle schemas. No server imports or secrets."""
from __future__ import annotations
import math,re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator
from qduel_sdk.rules import Rules
from duelkit.quantum import G, validate, ROTATIONS

GateName=Literal['rx','ry','rz','rxx','ryy','rzz','h','x','y','z','cx']
class Strict(BaseModel):
    model_config=ConfigDict(extra='forbid',allow_inf_nan=False)

def numeric_fields(value,keys):
    if isinstance(value,dict):
        for key in keys:
            a=value.get(key)
            if a is not None and (isinstance(a,bool) or not isinstance(a,(int,float))):
                raise ValueError(f'{key} must be a finite JSON number')
    return value

class GateInput(Strict):
    name: GateName
    targets:list[StrictInt]=Field(min_length=1,max_length=2)
    angle:float|None=None
    @model_validator(mode='before')
    @classmethod
    def numeric(cls,v):return numeric_fields(v,('angle',))
    @model_validator(mode='after')
    def gate(self):
        # Union-shaped boundary. Exact alphabet/dimension/angles come from the round.
        validate((G(self.name,tuple(self.targets),self.angle),),n=8)
        return self
    def gate_record(self):return G(self.name,tuple(self.targets),self.angle)

class ParameterRange(Strict):
    low:float
    high:float
    @model_validator(mode='before')
    @classmethod
    def numeric(cls,v):return numeric_fields(v,('low','high'))
    @model_validator(mode='after')
    def ordered(self):
        if not -math.pi<=self.low<=self.high<=math.pi:
            raise ValueError('Parameter range must be inside [-pi,pi]')
        return self

class TemplateGate(Strict):
    name:GateName
    targets:list[StrictInt]=Field(min_length=1,max_length=2)
    low:float|None=None
    high:float|None=None
    parameter:str|None=Field(default=None,pattern=r'^[A-Za-z][A-Za-z0-9_]{0,31}$')
    scale:float=1.0
    offset:float=0.0
    @model_validator(mode='before')
    @classmethod
    def numeric(cls,v):return numeric_fields(v,('low','high','scale','offset'))
    @model_validator(mode='after')
    def limits(self):
        if self.name in ROTATIONS:
            if self.parameter is not None:
                if self.low is not None or self.high is not None:
                    raise ValueError('Use a named parameter OR an independent range, not both')
                if self.scale not in (-1.0,1.0):
                    raise ValueError('Shared angles support scale +1 or -1 only')
                GateInput(name=self.name,targets=self.targets,angle=0.0)
            else:
                if self.scale!=1.0 or self.offset!=0.0:
                    raise ValueError('Affine transforms require a named parameter')
                if self.low is None or self.high is None or not -math.pi<=self.low<=self.high<=math.pi:
                    raise ValueError('Independent rotation ranges must be inside [-pi,pi]')
                GateInput(name=self.name,targets=self.targets,angle=(self.low+self.high)/2)
        else:
            if any(x is not None for x in (self.low,self.high,self.parameter)) or self.scale!=1 or self.offset!=0:
                raise ValueError('Fixed gates have no parameter fields')
            GateInput(name=self.name,targets=self.targets)
        return self

class Template(Strict):
    name:str=Field(min_length=1,max_length=64)
    parameters:dict[str,ParameterRange]=Field(default_factory=dict,max_length=72)
    gates:list[TemplateGate]=Field(min_length=1,max_length=72)
    @model_validator(mode='after')
    def shared_parameters(self):
        for name in self.parameters:
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,31}',name):raise ValueError('Invalid parameter name')
        used=set()
        for g in self.gates:
            if g.parameter is not None:
                if g.parameter not in self.parameters:raise ValueError('Undefined shared parameter')
                used.add(g.parameter);p=self.parameters[g.parameter]
                lo,hi=sorted((g.scale*p.low+g.offset,g.scale*p.high+g.offset))
                if not -math.pi<=lo<=hi<=math.pi:
                    raise ValueError('Transformed parameter leaves [-pi,pi]')
        if used!=set(self.parameters):raise ValueError('Unused template parameters')
        return self
class EntryInput(Strict):
    artifact_id: str=Field(pattern=r'^[a-f0-9]{32}$')
    attacks: list[Template]=Field(min_length=2,max_length=2)
    version: str=Field(min_length=1,max_length=40,pattern=r'^[\w. -]+$')
class Query(Strict):
    request_id: str=Field(min_length=1,max_length=100,pattern=r'^[a-zA-Z0-9_.:-]+$')
    experiment_index: StrictInt=Field(ge=0,lt=11019960576)
    shots: StrictInt=Field(ge=1,le=120000)
    analysis_patch: list[GateInput]=Field(default_factory=list,max_length=108)
class Patch(Strict):
    request_id: str=Field(min_length=1,max_length=100,pattern=r'^[a-zA-Z0-9_.:-]+$')
    patch: list[GateInput]=Field(default_factory=list,max_length=108)
    note: str=Field(default='',max_length=200)
class Action(Strict):
    request_id: str=Field(min_length=1,max_length=100,pattern=r'^[a-zA-Z0-9_.:-]+$')

class FailureReport(Action):
    code:Literal['DEFENDER_EXCEPTION']='DEFENDER_EXCEPTION'

class QueryBatch(Strict):
    experiments: list[Query] = Field(min_length=1, max_length=32)
    @model_validator(mode='after')
    def unique_requests(self):
        if len({q.request_id for q in self.experiments}) != len(self.experiments):
            raise ValueError('Batch request IDs must be unique')
        return self
