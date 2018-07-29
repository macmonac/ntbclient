#!/usr/bin/env python

import unittest
import sys
import os
# from pprint import pprint

# Don't generate pyc file
sys.dont_write_bytecode = True

cur_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(cur_dir, os.pardir, 'src')
print(src_dir)
sys.path.append(src_dir)

from ntbclient import is_ipv4_address, is_ipv6_address, get_servers


class NTBClientTest(unittest.TestCase):
    def test_ip_check(self):
        self.assertTrue(is_ipv4_address("127.0.0.1"))
        self.assertFalse(is_ipv4_address("::1"))
        self.assertTrue(is_ipv6_address("::1"))
        self.assertFalse(is_ipv6_address("127.0.0.1"))

    def test_get_servers(self):
        # SImple Test
        servers = get_servers("localhost", False, "all")
        expected = [{'host': 'localhost', 'ip': '127.0.0.1', 'port': '443'},
                    {'host': 'localhost', 'ip': '::1', 'port': '443'}
                    ]
        self.assertListEqual(servers, expected)

        # DNS, v4, v6 + ports
        servers = get_servers('localhost,192.168.0.1,fc00::1,[fc00::2],localhost:444,192.168.0.2:445,fc00::3:446,[fc00::4]:447', False, 'all')
        expected = [{'host': 'localhost', 'ip': '127.0.0.1', 'port': '443'},
                    {'host': 'localhost', 'ip': '::1', 'port': '443'},
                    {'host': '192.168.0.1', 'ip': '192.168.0.1', 'port': '443'},
                    {'host': 'fc00::1', 'ip': 'fc00::1', 'port': '443'},
                    {'host': 'fc00::2', 'ip': 'fc00::2', 'port': '443'},
                    {'host': 'localhost', 'ip': '127.0.0.1', 'port': '444'},
                    {'host': 'localhost', 'ip': '::1', 'port': '444'},
                    {'host': '192.168.0.2', 'ip': '192.168.0.2', 'port': '445'},
                    {'host': 'fc00::3:446', 'ip': 'fc00::3:446', 'port': '443'},
                    {'host': 'fc00::4', 'ip': 'fc00::4', 'port': '447'}
                    ]
        self.assertListEqual(servers, expected)

        # Empty String
        servers = get_servers('', False, 'all', False)
        expected = []
        self.assertListEqual(servers, expected)


if __name__ == '__main__':
    unittest.main()
