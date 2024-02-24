import re
import os

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

def parse_nmap_results(nmap_output):
    # Regular expressions to match open ports and banners
    port_pattern = re.compile(r'(\d+)\/(tcp|udp)\s+(open)\s+(.+)')
    example_pattern = re.compile(r'\s{2,}')
    wordpress_sites = []


    for line in nmap_output.split('\n'):
        port_match = port_pattern.match(line)

        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            service_info = port_match.group(4)


            serviceArr = example_pattern.split(service_info)
            version = ''
            service = ''
            if(len(serviceArr) < 2):
                version = None
                service = serviceArr[0]
            else:
                service= serviceArr[0]
                version = serviceArr[1]


            current_site={
                'port': port, 
                'protocol': protocol, 
                'state': state, 
                'service' : service,
                'version': version
            }
            wordpress_sites.append(current_site)

    return wordpress_sites


current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'namp.txt')
nmap_output = read_file(filePath)


parsed_sites = parse_nmap_results(nmap_output)
for site in parsed_sites:
    print(site)
    print('\n')

