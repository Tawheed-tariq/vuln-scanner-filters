import re
import os

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

# scrapes robots.txt, xml-RPC, Wordpress README, Wordpress Version from wp scan output
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


def find_vulnerabilities(wp_output):
    plugins_pattern = r'\[i\] Plugin\(s\) Identified:\n(.*)Interesting Finding\(s\):'

    plugins = re.search(plugins_pattern, wp_output, re.DOTALL)
    plugin_output = plugins.group(1).strip() #plugins part of the wp_output
    plugin_arr = re.findall(r'\[\+\]\s(.*?)\n\n',plugin_output , re.DOTALL) #scrapes all the plugins present in plugins



    vuln_pattern = r'vulnerabilities identified:(.*)'
    vulnerabilities = re.search(vuln_pattern,plugin_arr[0], re.DOTALL)
    pattern = r'\[!\](.*?)References'
    vuln_arr = re.findall(pattern , vulnerabilities.group(0).strip(), re.DOTALL)
    for vuln in vuln_arr:
        print(vuln + '\n')



def find_users(wp_output):
    users_pattern = r'\[i\] User\(s\) Identified:\n(.*)\[\+\] Finished'
    users = re.search(users_pattern, wp_output , re.DOTALL)
    users_output = users.group(1).strip()
    print(users_output)



current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'wpscan.txt')
wp_output = read_file(filePath)


# result = parse_wp_results(wp_output)
find_vulnerabilities(wp_output)
# find_users(wp_output)