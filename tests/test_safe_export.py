"""The source exporter must never bundle runtime data or credential material."""

from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from scripts.export_source import export_source


class SafeExportTests(unittest.TestCase):
    def test_allowlisted_export_excludes_runtime_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'app').mkdir()
            (root/'data').mkdir()
            (root/'credentials').mkdir()
            (root/'app'/'service.py').write_text('safe source',encoding='utf-8')
            (root/'app'/'private.key').write_text('DO-NOT-EXPORT',encoding='utf-8')
            (root/'data'/'cdss.db').write_text('DO-NOT-EXPORT',encoding='utf-8')
            (root/'credentials'/'password.txt').write_text('DO-NOT-EXPORT',encoding='utf-8')
            (root/'.env').write_text('DO-NOT-EXPORT',encoding='utf-8')
            destination=root/'source.zip'
            self.assertEqual(export_source(destination,root),1)
            with ZipFile(destination) as archive:
                self.assertEqual(archive.namelist(),['app/service.py'])
                self.assertNotIn(b'DO-NOT-EXPORT',archive.read('app/service.py'))
            with self.assertRaises(FileExistsError):
                export_source(destination,root)


if __name__=='__main__':
    unittest.main()
