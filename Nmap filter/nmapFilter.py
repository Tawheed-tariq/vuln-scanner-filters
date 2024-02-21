import re

def parse_nmap_results(nmap_output):
    # Regular expressions to match open ports and banners
    port_pattern = re.compile(r'(\d+)\/(tcp|udp)\s+(open)\s+(.+)')
    banner_pattern = re.compile(r'Nmap scan report for (.+)')
    service_pattern = re.compile(r'Service Info: (.+)')

    wordpress_sites = []

    current_site = None

    for line in nmap_output.split('\n'):
        port_match = port_pattern.match(line)
        banner_match = banner_pattern.match(line)
        service_match = service_pattern.match(line)



        if port_match:
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            service_info = port_match.group(4)
            # Check if the service might be related to WordPress


            # if 'http' in service_info.lower():
            current_site = {'ports': [], 'services': []}
            current_site['ports'].append({
                'port': port, 
                'protocol': protocol, 
                'state': state, 
                'service_info': service_info
            })
            wordpress_sites.append(current_site)
            # else:
                # current_site = None




        elif banner_match:
            if current_site:
                current_site['banner'] = banner_match.group(1)

        elif service_match:
            if current_site:
                current_site['services'].append(service_match.group(1))

    return wordpress_sites

# port example
#80 -> port
#tcp -> protocol
#open -> starus
#http    Apache httpd 2.4.29 ((Ubuntu)) -> service

# Example usage:
nmap_output = """
# Nmap 7.94SVN scan initiated Wed Feb 21 05:56:35 2024 as: nmap -sV -A -T5 -o nmap.txt 216.10.253.176
Warning: 216.10.253.176 giving up on port because retransmission cap hit (2).
Nmap scan report for 216.10.253.176
Host is up (0.13s latency).
Not shown: 710 closed tcp ports (conn-refused), 276 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Pure-FTPd
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|_  1024 22:17:d9:d4:2a:e0:33:af:6d:92:4b:f3:06:69:18:74 (DSA)
26/tcp   open  smtp       Exim smtpd 4.96.2
| smtp-commands: md-in-56.webhostbox.net Hello nmap.scanme.org [169.149.192.213], SIZE 52428800, 8BITMIME, PIPELINING, PIPECONNECT, AUTH PLAIN LOGIN, STARTTLS, HELP
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
80/tcp   open  http       Apache httpd
| http-title: Site doesn't have a title (text/html).
|_Requested resource was /404.html
110/tcp  open  pop3       Dovecot pop3d
|_pop3-capabilities: TOP RESP-CODES UIDL STLS SASL(PLAIN LOGIN) AUTH-RESP-CODE USER CAPA PIPELINING
| ssl-cert: Subject: commonName=*.webhostbox.net
| Subject Alternative Name: DNS:*.webhostbox.net, DNS:webhostbox.net
| Not valid before: 2023-06-20T00:00:00
|_Not valid after:  2024-06-01T23:59:59
143/tcp  open  imap       Dovecot imapd
| ssl-cert: Subject: commonName=*.webhostbox.net
| Subject Alternative Name: DNS:*.webhostbox.net, DNS:webhostbox.net
| Not valid before: 2023-06-20T00:00:00
|_Not valid after:  2024-06-01T23:59:59
|_imap-capabilities: more SASL-IR NAMESPACE AUTH=PLAIN post-login LOGIN-REFERRALS listed have IMAP4rev1 LITERAL+ Pre-login OK STARTTLS IDLE ENABLE AUTH=LOGINA0001 ID capabilities
443/tcp  open  ssl/http   Apache httpd
| http-title: Site doesn't have a title (text/html).
|_Requested resource was /404.html
| ssl-cert: Subject: commonName=*.webhostbox.net
| Subject Alternative Name: DNS:*.webhostbox.net, DNS:webhostbox.net
| Not valid before: 2023-06-20T00:00:00
|_Not valid after:  2024-06-01T23:59:59
|_http-server-header: Apache
|_ssl-date: TLS randomness does not represent time
554/tcp  open  rtsp?
587/tcp  open  smtp       Exim smtpd 4.96.2
| ssl-cert: Subject: commonName=*.webhostbox.net
| Subject Alternative Name: DNS:*.webhostbox.net, DNS:webhostbox.net
| Not valid before: 2023-06-20T00:00:00
|_Not valid after:  2024-06-01T23:59:59
| smtp-commands: md-in-56.webhostbox.net Hello nmap.scanme.org [169.149.192.213], SIZE 52428800, 8BITMIME, PIPELINING, PIPECONNECT, AUTH PLAIN LOGIN, STARTTLS, HELP
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
993/tcp  open  imaps?
| ssl-cert: Subject: commonName=*.webhostbox.net
| Subject Alternative Name: DNS:*.webhostbox.net, DNS:webhostbox.net
| Not valid before: 2023-06-20T00:00:00
|_Not valid after:  2024-06-01T23:59:59
|_imap-capabilities: more SASL-IR NAMESPACE AUTH=PLAIN post-login have capabilities IMAP4rev1 LITERAL+ Pre-login listed OK IDLE ENABLE AUTH=LOGINA0001 ID LOGIN-REFERRALS
995/tcp  open  pop3s?
| ssl-cert: Subject: commonName=*.webhostbox.net
| Subject Alternative Name: DNS:*.webhostbox.net, DNS:webhostbox.net
| Not valid before: 2023-06-20T00:00:00
|_Not valid after:  2024-06-01T23:59:59
1723/tcp open  tcpwrapped
2222/tcp open  ssh        OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|_  1024 22:17:d9:d4:2a:e0:33:af:6d:92:4b:f3:06:69:18:74 (DSA)
3306/tcp open  mysql      MySQL 5.7.23-23
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.23-23
|   Thread ID: 114691393
|   Capabilities flags: 65535
|   Some Capabilities: DontAllowDatabaseTableColumn, Support41Auth, Speaks41ProtocolOld, LongPassword, SwitchToSSLAfterHandshake, SupportsTransactions, ODBCClient, LongColumnFlag, IgnoreSigpipes, InteractiveClient, ConnectWithDatabase, FoundRows, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, SupportsCompression, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=*.webhostbox.net
| Subject Alternative Name: DNS:*.webhostbox.net, DNS:webhostbox.net
| Not valid before: 2023-06-20T00:00:00
|_Not valid after:  2024-06-01T23:59:59
|_ssl-date: TLS randomness does not represent time
Service Info: Host: md-in-56.webhostbox.net

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 21 05:59:21 2024 -- 1 IP address (1 host up) scanned in 166.28 seconds"""




print('Parsing Nmap results...')
parsed_sites = parse_nmap_results(nmap_output)

# Display parsed WordPress sites
print('WordPress Sites:')
for site in parsed_sites:
    print("IP:", site['ports'][0]['service_info'].split()[0])
    print("Open Ports:", site['ports'])
    print("Services:", site['services'])
    print("Banner:", site.get('banner', 'N/A'))



