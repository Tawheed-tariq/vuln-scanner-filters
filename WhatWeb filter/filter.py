import re
import os

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'cleaned_whatweb.txt')


scan_output = read_file(filePath)

def filter_scan(scan_output):
    country_pattern = re.compile(r'Country\[(.*?)\]')
    server_pattern = re.compile(r'HTTPServer\[(.*?)\]')
    ip_pattern = re.compile(r'IP\[(.*?)\]')
    email_pattern = re.compile(r'Email\[(.*?)\]')


    country_match = country_pattern.search(scan_output)
    server_match = server_pattern.search(scan_output)
    ip_match = ip_pattern.search(scan_output)
    email_match = email_pattern.search(scan_output)

    matches = {
        'country' : country_match.group(1),
        'http server': server_match.group(1),
        'IP' : ip_match.group(1),
        'email' : email_match.group(1)
    }

    return matches


filter_result = filter_scan(scan_output)
print(filter_result)