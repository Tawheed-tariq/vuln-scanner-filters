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
    wordpress_version_pattern = re.compile(r'WordPress version (.+)')

    robots_match = robots_txt_pattern.search(wp_output)
    xml_match = xml_rpc_pattern.search(wp_output)
    wordpress_readme = wordpress_readme_pattern.search(wp_output)
    wordpress_version = wordpress_version_pattern.search(wp_output)

    matches = {
        'res' : '',
        'data' : {
            'headings' : ["Files", "Description"],
            'dataRows' : [
                ["Robots.txt", robots_match.group(1) if robots_match else 'None'],
                ['xml-RPC' , xml_match.group(1) if xml_match else 'None'],
                ['wordpress readme', wordpress_readme.group(1) if wordpress_readme else 'None'],
                ['wordpress version',  wordpress_version.group(1) if wordpress_version else 'NA'],
            ]
        }
    }
    matches['res'] = str(len(matches['data']['dataRows'])) + ' Intresting Enteries Found'
    return matches

#finds vulnerabilities of each plugin
def vuln_finder(vulnerabilities):
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
    return [num_of_vuln, vulns]

#scrapes the number of vulnerabilities and title, version of each vulnerability and returns an array (output data)
def find_vulnerabilities(wp_output):
    try:
        plugins_pattern = r'\[i\] Plugin\(s\) Identified:\n(.*?)(?:Interesting Finding\(s\):|Enumerating|\[i\])'
        plugins = re.search(plugins_pattern, wp_output, re.DOTALL)

        #if plugins are present then it will execute this code
        if(plugins):
            plugin_output = plugins.group(1).strip() #plugins part of the wp_output
            plugin_arr = re.findall(r'\[\+\]\s(.*?)\n\n',plugin_output , re.DOTALL) #scrapes all the plugins present in plugin_output

            #find vulnerabilities of each plugin
            output_data = {
                'res' : '',
                'data' : {
                    'headings' : ["Plugin","number", "vulnerabilities"],
                    'dataRows' : []
                }
            }
            number = 0
            for plugin in plugin_arr:
                plugin_name_pattern = r'(.*)'
                plugin_name = re.match(plugin_name_pattern, plugin).group(1)

                vuln_pattern = r'vulnerabilit.* identified:(.*)'
                vulnerabilities = re.search(vuln_pattern,plugin, re.DOTALL)

                # if the line "vulnerabilities identified" is present in plugin the this will execute
                if(vulnerabilities):
                    data = vuln_finder(vulnerabilities)
                    output_data['data']['dataRows'].append([plugin_name, data[0], data[1]])
                    number += data[0]
                else:
                    output_data['data']['dataRows'].append([plugin_name, 0, 'None'])
            output_data['res'] = str(number) + ' plugin Vulnerabilities Found'
            return output_data if len(output_data['data']['dataRows']) > 0 else None
    except:
        print('error')

def them_in_use(wp_output):
    try:
        theme_pattern = r'WordPress theme in use: (.*?)(?:\n\n|Enumerating|\[i\])'
        theme = re.search(theme_pattern, wp_output, re.DOTALL)
        if theme:
            theme_output = theme.group(1).strip()
            theme_name = re.match('(.*)', theme_output).group(1)
            vuln_pattern = r'vulnerabilit.* identified:(.*)'
            vulnerabilities = re.search(vuln_pattern,theme_output, re.DOTALL)
            if vulnerabilities:
                data = vuln_finder(vulnerabilities)
                return [theme_name, data[0], data[1]]
            else:
                return [theme_name, 0, 'None']
    except:
        print('error in theme')

def find_themes(wp_output):
    try:
        themes_pattern = r'\[i\] Theme\(s\) Identified:\n(.*?)(?:Interesting Finding\(s\):|Enumerating|\[i\])'
        themes = re.search(themes_pattern, wp_output, re.DOTALL)
        output_data = {
            'res' : '',
            'data' : {
                'headings' : ["Theme","number", "vulnerabilities"],
                'dataRows' : []
            }
        }
        number = 0
        in_use_theme = them_in_use(wp_output)
        output_data['data']['dataRows'].append(in_use_theme)
        number = in_use_theme[1]
        if themes:
            themes_output = themes.group(1).strip()
            themes_arr = re.findall(r'\[\+\]\s(.*?)\n\n',themes_output , re.DOTALL)
            for theme in themes_arr:
                theme_name_pattern = r'(.*)'
                theme_name = re.match(theme_name_pattern, theme).group(1)

                vuln_pattern = r'vulnerabilit.* identified:(.*)'
                vulnerabilities = re.search(vuln_pattern,theme, re.DOTALL)
                if(vulnerabilities):
                    data = vuln_finder(vulnerabilities)
                    output_data['data']['dataRows'].append([theme_name, data[0], data[1]])
                    number += data[0]
                else:
                    output_data['data']['dataRows'].append([theme_name, 0, 'None'])
        output_data['res'] = str(number) + ' theme vulnerabilities Found'
        return output_data if len(output_data['data']['dataRows']) > 0 else None      
    except:
        print('error in themes')


def find_users(wp_output):
    users_pattern = r'\[i\] User\(s\) Identified:\n(.*?)(?:\[\+\] WPScan DB API|\[\+\] Finished|$)'
    users = re.search(users_pattern, wp_output , re.DOTALL)

    response = {
        'res' : '',
        'data' : {
            'headings' : ["username"],
            'dataRows' : []
        }
    }
    if users:
        users_output = users.group(1).strip()
        pattern = r'\[\+\](.*)'
        users_arr = re.findall(pattern, users_output)

        for user in users_arr:
            response['data']['dataRows'].append([user])
        response['res'] = str(len(response['data']['dataRows'])) + ' User(s) Found'

        return response

        



current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'wpscan5.txt')
wp_output = read_file(filePath)


result = parse_wp_results(wp_output)
print(result)
print('\n')


vulnerabilities = find_vulnerabilities(wp_output)
if(vulnerabilities):
    print(vulnerabilities)
else:
    print(f"vulnerabilities are : {vulnerabilities}")


users = find_users(wp_output)
print(users)

themes = find_themes(wp_output)
print(themes)