"""Verify caller bytes against checked-out Git objects, compile, then pure controls."""
from pathlib import Path
import subprocess
import sys
import unittest

HERE=Path(__file__).resolve().parent
def main():
    root=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],cwd=HERE,text=True,timeout=10).strip())
    for name in ('caller.py','test_caller.py','source_check.py'):
        path=HERE/name
        if path.is_symlink() or path.stat().st_nlink!=1: raise ValueError('Nonregular caller source')
        relative=path.relative_to(root).as_posix()
        raw=subprocess.check_output(['git','cat-file','blob','HEAD:'+relative],cwd=root,timeout=10)
        if path.read_bytes()!=raw: raise ValueError('Caller differs from exact checked-out source')
        compile(raw,str(path),'exec')
    for optimized in (False,True):
        argv=[sys.executable,'-B']+(['-O'] if optimized else [])+[str(Path(__file__).resolve()),'--child']
        subprocess.run(argv,cwd=HERE,timeout=25,check=True)
if __name__=='__main__':
    if sys.argv[1:]==['--child']:
        for name in ('caller.py','test_caller.py','source_check.py'):
            compile((HERE/name).read_bytes(),str(HERE/name),'exec')
        import test_caller as tests
        tests.BACKEND=HERE.parent.parent
        suite=unittest.defaultTestLoader.loadTestsFromModule(tests)
        if suite.countTestCases()!=18:raise ValueError('Exact caller controls required')
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    elif not sys.argv[1:]:main()
    else:raise ValueError('Unknown source-check arguments')
