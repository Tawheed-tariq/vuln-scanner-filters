import re
import os

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'wpscan.txt')
wp_output = read_file(filePath)


def parse_wp_results(wp_output):
    robots_txt_pattern = re.compile(r'robots.txt found: (.*)')
    xml_rpc_pattern = re.compile(r'XML-RPC seems to be enabled: (.*)')
    wordpress_readme_pattern = re.compile(r'WordPress readme found: (.*)')
    wordpress_version_pattern = re.compile(r'WordPress version (.+?)\s')

    robots_match = robots_txt_pattern.search(wp_output)
    xml_match = xml_rpc_pattern.search(wp_output)
    wordpress_readme = wordpress_readme_pattern.search(wp_output)
    wordpress_version = wordpress_version_pattern.search(wp_output)

    matches = {
        'robots.txt' : robots_match.group(1),
        'xml-RPC' : xml_match.group(1),
        'wordpress readme' : wordpress_readme.group(1),
        'wordpress version' : wordpress_version.group(1)
    }

    return matches


result = parse_wp_results(wp_output=wp_output)
print(result)