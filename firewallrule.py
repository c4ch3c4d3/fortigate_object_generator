# pylint: disable=C0301, C0103

from argparse import ArgumentParser
from ipaddress import IPv4Network


#import re

def main():
    """ Main Program """
    parser = ArgumentParser(
        description='Provided a list of ip addresses, format and output the correct fortigate commands to create them')
    parser.add_argument('vdom', help='Specify a vdom')
    parser.add_argument('File', help='Specify a file.  Each entry should be on its own line, and have no extra characters')
    args = parser.parse_args()

    with open(args.File, 'r') as input_file:
        array = input_file.read().splitlines()

    with open(args.vdom + '.txt', 'w') as output_file:
        output_file.write("config vdom\n")
        output_file.write("edit %s\n" % str(args.vdom))
        output_file.write("config firewall address\n\n")

        for i in range(0, len(array)):
            try:
                ip_addr = IPv4Network(array[i])
                generateip(ip_addr, output_file)
            except ValueError:
                url = array[i]
                generateurl(url, output_file)


def generateip(ip_addr, output_file):
    """
    Generate a single ip address object.

    ip_addr -- IP address network object
    output_file -- an output text file
    """
    output_file.write("edit \"%s\"\n" % str(ip_addr.with_prefixlen))
    output_file.write("set color 1\n")
    #import pdb; pdb.set_trace()
    output_file.write("set subnet %s %s\n" % (str(ip_addr.network_address), str(ip_addr.netmask)))
    output_file.write("next\n\n")


def generateurl(url, output_file):
    """
    Generate a single ip address object.

    url -- A valid URL string
    output_file -- an output text file
    """

    output_file.write("edit %s\n" % url)
    output_file.write("set color 1\n")
    output_file.write("set type fqdn\n")
    output_file.write("set fqdn %s\n" % url)
    output_file.write("next\n\n")


if __name__ == '__main__':
    main()



#def addtogrp():


# formataddrs()

# generateurl()

# generateip()

# addtogrp()

# print(iplist)
