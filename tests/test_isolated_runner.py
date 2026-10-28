"""The offline runner must reject SQLite aliases of protected storage."""
from pathlib import Path
import ast
from types import SimpleNamespace
import unittest


class IsolatedRunnerTests(unittest.TestCase):
    def setUp(self):
        # Compile only the runner's guard: importing the CLI runs the full suite.
        # A fake transport ensures a missed guard can never open real storage.
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root/'scripts/run_isolated_checks.py').read_text())
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                     and n.name in ('connect', 'targets_database')]
        from urllib.parse import unquote, urlsplit
        self.allowed = object()
        namespace = dict(ROOT=root, Path=Path, database=SimpleNamespace(DATABASE=root/'outer.db'),
                         original_connect=lambda *a, **kw: self.allowed,
                         unquote=unquote, urlsplit=urlsplit)
        exec(compile(ast.Module(body=functions,type_ignores=[]), '<runner guard>', 'exec'), namespace)
        self.connect = namespace['connect']

    def test_sqlite_uri_and_filesystem_aliases_resolve_to_protected_database(self):
        main = Path('data/cdss.db').resolve()
        for value in (str(main), 'data/cdss.db', main.as_uri()+'?mode=rw',
                      'file:data/cdss.db?mode=rw', 'file:'+str(main)+'?mode=rw',
                      main.as_uri().replace('cdss.db','%63dss.db')+'?mode=ro'):
            with self.subTest(target=value):
                with self.assertRaises(RuntimeError):
                    self.connect(value, uri=str(value).startswith('file:'))

    def test_disposable_database_and_memory_are_allowed(self):
        main = Path('data/cdss.db').resolve()
        for value in (':memory:', 'file:temporary?mode=memory&cache=shared',
                      'file:data/disposable.db?mode=rw'):
            self.assertIs(self.connect(value, uri=value.startswith('file:')), self.allowed)
