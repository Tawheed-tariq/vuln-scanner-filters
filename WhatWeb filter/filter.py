#whatweb leadgenapp.io | sed 's/\x1b\[[0-9;]*m//g' > cleaned_whatweb.txt

import re
import os

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()


def filter_scan(scan_output):
    #regular expression patterns
    country_pattern = re.compile(r'Country\[(.*?)\]')
    server_pattern = re.compile(r'HTTPServer\[(.*?)\]')
    ip_pattern = re.compile(r'IP\[(.*?)\]')
    email_pattern = re.compile(r'Email\[(.*?)\]')
    bst_pattern = re.compile(r'Bootstrap\[(.*?)\]')
    jquery_pattern = re.compile(r'JQuery\[(.*?)\]')
    title_pattern = re.compile(r'JQuery\[.*?:(.*?)\]')

    #matches of the patterns
    country_match = country_pattern.search(scan_output)
    server_match = server_pattern.search(scan_output)
    ip_match = ip_pattern.search(scan_output)
    email_match = email_pattern.search(scan_output)
    bootstrap_match = bst_pattern.search(scan_output)
    jquery_match = jquery_pattern.search(scan_output)
    title_match = title_pattern.search(scan_output)

    matches = {
        'res' : '',
        'data' : {
            'headings' : ["Title","Country", "HTTP Server", "IP", "Email", "Bootstrap Version", "Jquery Version"],
            'dataRows' : [
                title_match.group(1) if title_match else '',
                country_match.group(1) if country_match else '',
                server_match.group(1) if server_match else '',
                ip_match.group(1) if ip_match else '',
                email_match.group(1) if email_match else '',
                bootstrap_match.group(1) if bootstrap_match else '',
                jquery_match.group(1) if jquery_match else ''
            ]
        }
    }
    matches['res'] = 'Genral Info'
    return matches


current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'cleaned_whatweb.txt')
scan_output = read_file(filePath)


filter_result = filter_scan(scan_output)
print(filter_result)