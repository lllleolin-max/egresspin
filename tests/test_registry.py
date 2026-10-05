"""Published IANA facts, not product registry as the expected-value oracle."""
import unittest
from egresspin import Policy

class RegistryTests(unittest.TestCase):
    def test_current_non_global_and_more_specific_exceptions(self):
        p=Policy(('http://public.example',))
        for value in ['192.88.99.2','::ffff:192.88.99.2','100:0:0:1::1','5f00::1','192.0.0.8','2001:2::1','64:ff9b:1::1']:
            with self.subTest(value=value):self.assertFalse(p.permits(value))
        for value in ['192.0.0.9','192.0.0.10','::ffff:192.0.0.9','2001:1::3','2001:3::1','2001:20::1','8.8.8.8','2606:4700:4700::1111']:
            with self.subTest(value=value):self.assertTrue(p.permits(value))
        self.assertTrue(Policy(('http://public.example',),testing_ips=('::ffff:127.0.0.1',)).permits('127.0.0.1'))
