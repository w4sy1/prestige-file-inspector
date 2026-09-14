from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from app import inspect

class InspectorTests(unittest.TestCase):
    def test_magic_and_hash(self):
        with tempfile.TemporaryDirectory() as d,patch('app.powershell',return_value={'status':'Unknown'}):
            p=Path(d)/'fake.txt';p.write_bytes(b'\x89PNG\r\n\x1a\n')
            r=inspect(p);self.assertEqual(r['mime_by_magic'],'image/png');self.assertEqual(len(r['hashes']['sha512']),128)
    def test_empty(self):
        with tempfile.TemporaryDirectory() as d,patch('app.powershell',return_value={}):
            p=Path(d)/'empty';p.touch();self.assertEqual(inspect(p)['entropy_bits_per_byte'],0)
    def test_strings_opt_in(self):
        with tempfile.TemporaryDirectory() as d,patch('app.powershell',return_value={}):
            p=Path(d)/'file';p.write_bytes(b'example text')
            self.assertEqual(inspect(p)['strings'],[]);self.assertTrue(inspect(p,True)['strings'])
