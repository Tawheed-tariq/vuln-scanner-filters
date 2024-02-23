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
        'robots.txt' : robots_match.group(1) if robots_match else '',
        'xml-RPC' : xml_match.group(1) if xml_match else '',
        'wordpress readme' : wordpress_readme.group(1) if wordpress_readme else '',
        'wordpress version' : wordpress_version.group(1) if wordpress_version else ''
    }

    return matches

#scrapes the number of vulnerabilities and title, version of each vulnerability and returns an array (output data)
def find_vulnerabilities(wp_output):
    try:
        plugins_pattern = r'\[i\] Plugin\(s\) Identified:\n(.*?)(?:Interesting Finding\(s\):|\[i\])'

        plugins = re.search(plugins_pattern, wp_output, re.DOTALL)
        plugin_output = plugins.group(1).strip() #plugins part of the wp_output
        plugin_arr = re.findall(r'\[\+\]\s(.*?)\n\n',plugin_output , re.DOTALL) #scrapes all the plugins present in plugin_output

        #find vulnerabilities of each plugin
        output_data = []
        for plugin in plugin_arr:
            vuln_pattern = r'vulnerabilit.* identified:(.*)'
            vulnerabilities = re.search(vuln_pattern,plugin, re.DOTALL)


            # if the line "vulnerabilities identified" is present in plugin the this will execute
            if(vulnerabilities):
                pattern = r'\[!\](.*?)References'
                vuln_arr = re.findall(pattern , vulnerabilities.group(0).strip(), re.DOTALL)
                num_of_vuln = len(vuln_arr)

                #find title and version of each vulnerability
                vulns = []
                for vuln in vuln_arr:
                    title_pattern = re.compile(r'Title: (.*)')
                    fixed_pattern = re.compile(r'Fixed in: (.*)')

                    title = title_pattern.search(vuln)
                    fixed = fixed_pattern.search(vuln)

                    data = {
                        'title' : title.group(1),
                        'Version' : fixed.group(1)
                    }
                    vulns.append(data)


                plugin_vuln_data = {
                    'number' : num_of_vuln,
                    'vulns' : vulns
                }
                output_data.append(plugin_vuln_data)
        return output_data
    except:
        print('error')



def find_users(wp_output):
    users_pattern = r'\[i\] User\(s\) Identified:\n(.*)\[\+\] Finished'
    users = re.search(users_pattern, wp_output , re.DOTALL)
    users_output = users.group(1).strip()
    print(users_output)



current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'wpscan.txt')
wp_output = read_file(filePath)


# result = parse_wp_results(wp_output)
# print(result)
# print('\n')
vulnerabilities = find_vulnerabilities(wp_output)
for vuln in vulnerabilities:
    print(vuln)
    print('\n')
# find_users(wp_output)