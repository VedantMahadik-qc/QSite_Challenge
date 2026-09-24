"""Fresh trusted-local process for a student practice case; NOT a sandbox."""
import importlib.util, inspect, json, sys
from pathlib import Path
from .rules import Rules
from .contracts import Template
from .templates import instantiate
from .profiles import practice_bank
from .local import LocalSession

def main():
    cfg=json.loads(Path(sys.argv[1]).read_text());output=Path(cfg['result']);session=None
    try:
        rules=Rules(**cfg['rules']);case=cfg['case'];bank=practice_bank(rules)
        if case not in bank:raise ValueError('Unknown public practice case')
        attack=instantiate(Template(**bank[case]),cfg['seed'],rules)
        session=LocalSession(attack,rules,seed=cfg['seed']+100000)
        root=Path(cfg['source']);sys.path.insert(0,str(root))
        spec=importlib.util.spec_from_file_location('participant_main',root/'main.py')
        module=importlib.util.module_from_spec(spec);sys.modules['participant_main']=module;spec.loader.exec_module(module)
        if not callable(getattr(module,'run',None)):raise ValueError('Missing callable run(client, rules)')
        value=module.run(session.client(),rules)
        if inspect.isawaitable(value) or inspect.isgenerator(value):raise ValueError('run must execute synchronously, not return a coroutine or generator')
        session.client().finish()
        output.write_text(json.dumps(dict(status='PASSED',**session.result())))
        return 0
    except BaseException as exc:
        output.write_text(json.dumps(dict(status='FAILED',error=f'{type(exc).__name__}: {str(exc)[:500]}',
             spent_shots=session.status()['spent_shots'] if session else 0)))
        return 1
if __name__=='__main__':raise SystemExit(main())
