#############################################
# test_setup.py:                            #
# This script creates a config file used by #
# the unit tests. The file producd contains # 
# the MAC and IP addresses for all of the   #
# router's interfaces and the IPs for the   #
# servers. It should be run before any test # 
# by the root node in mininet, i.e. by      #
# running either:                           #
# 1) mininet> root python test_setup.py     #
#    or                                     #
# 2) mininet> xterm root                    #
# and from the root node's terminal run     #
# >> python test_setup.py                   #
#############################################


import socket, fcntl, struct, re


TEST_CONFIG_PATH = '/home/ubuntu/cs144_lab3/router/tests/tmp/TESTCONFIG.txt'
IP_CONFIG_PATH = '/home/ubuntu/cs144_lab3/IP_CONFIG'

# get_mac_addr was taken from                                                               
# http://stackoverflow.com/questions/159137/getting-mac-address                             
def get_mac_addr (ifname):
    s = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl (s.fileno (), 0x8927,  struct.pack ('256s', ifname[:15]))
    s.close ()
    return ''.join (['%02x:' % ord (char) for char in info[18:24]])[:-1]

# get_ip_addr taken from
# http://code.activestate.com/recipes/439094-get-the-ip-address-associated-with-a-network-inter/
def get_ip_addr (ifname):
    s = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
    ip_addr = socket.inet_ntoa (fcntl.ioctl (
        s.fileno (),
        0x8927,
        struct.pack ('256s', ifname[:15])
        )[20:24])
    s.close ()
    return ip_addr

def find_first_match_in_array (array, regex):
    for line in array: 
        m = re.match (regex, line)
        if m:
            return m.group(1)
    return None

def main ():
    f = open (TEST_CONFIG_PATH, 'w')
   
    f.write ("# This file contains the IP and MAC addresses for\n" + \
            "# the interfaces eth1, eth2, and eth3 in the router,\n" + \
            "# as well as the IPs for the http servers.\n" + \
            "# This file is automatically generated by the script\n" + \
            "# test_setup.py. DO NOT modify the contents of this file.\n" + \
            "# The file follows the following format: \n#\n" + \
            "# ETH1_MAC_ADDR\n" + \
            "# ETH2_MAC_ADDR\n" + \
            "# ETH3_MAC_ADDR\n" + \
            "# ETH1_IP_ADDR\n" + \
            "# ETH2_IP_ADDR\n" + \
            "# ETH3_IP_ADDR\n" + \
            "# SERVER1_IP_ADDR\n" + \
            "# SERVER2_IP_ADDR\n#\n")
    f.write (get_mac_addr ("sw0-eth1") + "\n")
    f.write (get_mac_addr ("sw0-eth2") + "\n")
    f.write (get_mac_addr ("sw0-eth3") + "\n")
    
    lines = [line.strip () for line in open (IP_CONFIG_PATH)]
    eth1_pattern = r'^sw0-eth1 ([0-9\.]*)$'
    eth2_pattern = r'^sw0-eth2 ([0-9\.]*)$'
    eth3_pattern = r'^sw0-eth3 ([0-9\.]*)$'
    server1_pattern = r'^server1 ([0-9\.]*)$'
    server2_pattern = r'^server2 ([0-9\.]*)$'

    f.write (find_first_match_in_array (lines, eth1_pattern) + "\n")
    f.write (find_first_match_in_array (lines, eth2_pattern) + "\n")
    f.write (find_first_match_in_array (lines, eth3_pattern) + "\n")
    f.write (find_first_match_in_array (lines, server1_pattern) + "\n")
    f.write (find_first_match_in_array (lines, server2_pattern) + "\n")

    f.close ()

if __name__ == '__main__':
    main ()