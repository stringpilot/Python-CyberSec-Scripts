import re
import sys
import ipaddress
import requests



# input txt file for sorting, (Attempt to find a way on making a user input a file via cmd sys.argv() command or something)

insertfile = open("test.txt", 'r')

# regex for ip - arranging and compiling
ipRegex = re.compile(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}')
# create a subdomain regex
subDomainRegex = re.compile(r'(https?:\/\/)?([w]{3}\.)?(\w*.\w*)([\/\w]*)')

# function that spins up the regex as creates a text output

ip_addresses = []
for i, line in enumerate(insertfile):
    for match in re.finditer(ipRegex, line):
        ip_addresses.append(('Found on line %s: %s' % (i+1, match.group())))

insertfile.seek(0)

subdomains = []
for r, subdomain in enumerate(insertfile):
    for submatch in re.findall(subDomainRegex, subdomain):
        subdomains.append(('Found on line %s: %s' % (r+1, submatch)))
    

insertfile.close()

# Output results to a text file
output_file = open("output.txt", "w")
output_file.write("IP addresses found:\n")
for address in ip_addresses:
    output_file.write(address + '\n')

output_file.write("\nSubdomains found:\n")
for subdomain in subdomains:
    output_file.write(subdomain + '\n')
output_file.close()
