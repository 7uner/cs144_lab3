from scapy.all import *
import unittest
import os
import fcntl, socket, struct
from testsetup import get_mac_addr


TEST_CONFIG_PATH = '/home/ubuntu/cs144_lab3/router/tests/tmp/TESTCONFIG.txt'
SERVER1_TEST_PATH = "/home/ubuntu/http_server1/tests"
SERVER2_TEST_PATH = "/home/ubuntu/http_server2/tests"

# Ethernet header field codes
BROADCAST_ETH = "ff:ff:ff:ff:ff:ff"
ETHERTYPE_ARP = 0x806
ETHERTYPE_IP = 0x800

# Arp header field codes
ARP_HWTYPE_ETHERNET = 0x1
ARP_PTYPE_IP = 0x800
ETHR_ADDR_LEN = 6
IP_ADDR_LEN = 4
ARP_OPCODE_REQUEST = 0x1
ARP_OPCODE_REPLY = 0x2

class TestARP (unittest.TestCase):
    def read_test_config_file (self):
        f = open (TEST_CONFIG_PATH, 'r')
        
        while (True):
            line = f.readline ()
            if line[0] != '#':
                break
        
        self.eth1_mac_addr = line.strip ()
        self.eth2_mac_addr = f.readline ().strip ()
        self.eth3_mac_addr = f.readline ().strip ()
        self.eth1_ip_addr = f.readline ().strip ()
        self.eth2_ip_addr = f.readline ().strip ()
        self.eth3_ip_addr = f.readline ().strip ()
        self.server1_ip_addr = f.readline ().strip ()
        self.server2_ip_addr = f.readline ().strip ()

        f.close ()

    def setUp (self):
        self.read_test_config_file ()
        cwd = os.getcwd ()
        if cwd == SERVER1_TEST_PATH:
            self.host = "server1"
            self.host_eth = get_mac_addr ("server1-eth0")
            self.host_ip = self.server1_ip_addr
            self.rtr_if_eth = self.eth1_mac_addr
            self.rtr_if_ip = self.eth1_ip_addr

        elif cwd == SERVER2_TEST_PATH:
            self.host ="server2"
            self.host_eth = get_mac_addr ("server2-eth0")
            self.host_ip = self.server2_ip_addr
            self.rtr_if_eth = self.eth2_mac_addr
            self.rtr_if_ip = self.eth2_ip_addr
        else:
            self.fail ("Unrecongnized host. In cwd: " + cwd)

    def test_arp_request_from_server_to_rtr (self):
        arp_req = Ether (dst = BROADCAST_ETH) / ARP (pdst = self.rtr_if_ip)
        ans, unans = srp (arp_req, timeout = 2)

        try:
            reply = ans[0][1]
        except Exception:
            msg = "In test_arp_request_from_server: " + \
            "Did not receive an arp reply from router for arp request. Host: " + \
            self.host
            self.fail (msg)
        
        # check ethernet header values are correct
        self.assertEqual (reply.dst, self.host_eth)
        self.assertEqual (reply.src, self.rtr_if_eth)
        self.assertEqual (reply.type, ETHERTYPE_ARP)

        # check arp header values are correct 
        self.assertEqual (reply.hwtype, ARP_HWTYPE_ETHERNET)
        self.assertEqual (reply.ptype, ARP_PTYPE_IP)
        self.assertEqual (reply.hwlen, ETHR_ADDR_LEN)
        self.assertEqual (reply.plen, IP_ADDR_LEN)
        self.assertEqual (reply.op, ARP_OPCODE_REPLY)
        self.assertEqual (reply.hwsrc, self.rtr_if_eth)
        self.assertEqual (reply.psrc, self.rtr_if_ip)
        self.assertEqual (reply.hwdst, self.host_eth)
        self.assertEqual (reply.pdst, self.host_ip)
        
if __name__ == '__main__':
    unittest.main ()
