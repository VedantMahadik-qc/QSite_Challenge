"""Receipt-only client. No hidden-circuit or live-score interface."""
import time,uuid,httpx
from duelkit.quantum import circuit_data,experiment_index
from .rules import Rules

class OracleClient:
    def __init__(self,origin,capability,transport=None):
        # No keep-alive: a persistent connection pins a runner to one oracle replica for the whole encounter,
        # so replicas added by the autoscaler stay idle (observed 2026-09-19: 2 of 9 pods saturated). A fresh
        # in-cluster TCP connection per request costs ~1 ms against ~30 ms of oracle work.
        self.http=httpx.Client(base_url=origin.rstrip('/'),headers={'Authorization':'Bearer '+capability,'Connection':'close'},
            timeout=30,trust_env=False,follow_redirects=False,transport=transport,
            limits=httpx.Limits(max_keepalive_connections=0,max_connections=4))
        self.counter=0
    def _id(self,kind):self.counter+=1;return f'{kind}-{self.counter}-{uuid.uuid4().hex[:10]}'
    def _request(self,path,payload=None):
        # Retry only read operations or writes carrying the same idempotency key.
        for attempt in range(4):
            try:
                r=self.http.get(path) if payload is None else self.http.post(path,json=payload)
                if r.status_code in (429,502,503,504) and attempt<3:
                    delay=0.25*2**attempt
                    try:delay=max(delay,min(60.0,max(0.0,float(r.headers.get('Retry-After',delay)))))
                    except ValueError:pass
                    time.sleep(delay);continue
                if r.status_code>=400:
                    try:detail=r.json().get('detail',f'Oracle error {r.status_code}')
                    except (ValueError,AttributeError):detail=f'Oracle error {r.status_code}'
                    raise ValueError(str(detail)[:220])
                return r
            except httpx.TransportError:
                if attempt==3:raise
                time.sleep(0.25*2**attempt)
    def _call(self,path,payload=None):
        return self._request(path,payload).json()
    def status(self):return self._call('/v1/status')
    def execution_started(self):
        return self._call('/v1/execution-started',{'request_id':self._id('started')})
    def query_batch(self,experiments):
        """Up to 32 ordinary Query dictionaries; caller supplies stable request IDs.
        Entire batch commits or none does. Counts remain ordinary per-setting receipts.
        """
        from .contracts import QueryBatch
        body=QueryBatch(experiments=experiments)
        return self._call('/v1/query-batch',body.model_dump())['receipts']
    def query(self,index,shots,request_id,analysis_patch=()):
        return self._call('/v1/query',{'request_id':request_id,'experiment_index':int(index),'shots':int(shots),
                                     'analysis_patch':circuit_data(analysis_patch)})
    def query_experiment(self,prep,basis,shots,request_id,analysis_patch=()):
        rules=Rules(**self.status()['rules'])
        index=experiment_index(prep,basis,rules.qubits)
        return self.query(index,shots,request_id,analysis_patch)
    def submit_patch(self,patch,note=''):
        return self._call('/v1/patch',{'request_id':self._id('patch'),'patch':circuit_data(patch),'note':note})
    def close_checkpoint(self):return self._call('/v1/checkpoint',{'request_id':self._id('close')})
    def report_failure(self):return self._call('/v1/failure',{'request_id':self._id('failure'),'code':'DEFENDER_EXCEPTION'})
    def finish(self):return self._call('/v1/finish',{'request_id':self._id('finish')})
    def artifact(self):
        r=self._request('/v1/artifact');return r.content,r.headers['X-Artifact-SHA256']
    def close(self):self.http.close()
