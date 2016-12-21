# Fortigate Address & Service Object Creator

Usage: cli.py [-avs] File

Provided a list of ports or IPs & URLs, mass generate Fortigate firewall objects.

The input file can be either a .txt or .csv.

.txt files should contain only your entries, each on its own line, and no extra characters.
A valid .txt entry is either an IP/CIDR (ex. 192.168.1.0/24), an IP/Netmask (ex. 192.168.1.0/255.255.255.0), a URL (ex. www.purple.com), or a valid port between 1-65535.
Ports CANNOT be mixed with IPs & URLs.

.csv files should contain 5 fields.
IP Address Fields:
1. IP, IP/CIDR, IP/Netmask or URL
2. Netmask (needed if you do not provide a CIDR in the previous field) (Optional)
3. Interface to attach object to (Optional)
4. Custom Name for the object (Optional)
5. Comment to label the object (Optional)

Port Fields:
1. A valid protocol (tcp/udp) or 'both' for tcp & udp.
2. Destination port or port range (denoted with a -)
3. Source port or port range (Optional)
4. Custom name for the object (Optional)
5. Comment to label the object (Optional)

.csv's should be formatted similarly to an Excel .csv


DISCLAIMER: If you run something on a firewall that you shouldn't have, we are NOT responsible. READ YOUR CODE BEFORE YOU PLACE IT!!!

Requires Python 3
