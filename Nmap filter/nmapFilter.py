import re
import os

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

def get_version(service_info):
    example_pattern = re.compile(r'\s{2,}')
    serviceArr = example_pattern.split(service_info)
    version = ''
    service = ''
    if(len(serviceArr) < 2):
        version = None
        service = serviceArr[0]
    else:
        service= serviceArr[0]
        version = serviceArr[1]
    if(service[-1] == '?'):
        service = service[:len(service)-1]
    data = [service, version]
    return data

def parse_nmap_results(nmap_output):
    # Regular expressions to match open ports and banners
    port_pattern = re.compile(r'(\d+)\/(tcp|udp)\s+(open)\s+(.+)')
    wordpress_sites = {
        'headings' : ["Port, Protocol, Status, Service, Version"],
        'dataRows' : []
    }


    for line in nmap_output.split('\n'):
        port_match = port_pattern.match(line)

        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            service_info = port_match.group(4)

            data = get_version(service_info) #recieves the version and service 
            
            current_site=[port, protocol, state]
            current_site.extend(data)
            wordpress_sites['dataRows'].append(current_site)

    return wordpress_sites


current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'namp.txt')
nmap_output = read_file(filePath)


parsed_sites = parse_nmap_results(nmap_output)
for site in parsed_sites['dataRows']:
    print(site)