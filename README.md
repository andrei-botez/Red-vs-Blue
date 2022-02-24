# Red-vs-Blue
# Attack a web server, and monitor its logs generated during the attack

Summary:
'
This project was ran in Azure Cloud, using Hyper-V Manager on a Windows machine. The three virtual machines deployed off Hyper-V are: 

1. The "Capstone VM" - Hostname: Server 1, running the Web Server, FileBeat, MetricBeat and PacketBeat. 
2. The logs generates are then sent out to the second machine, the "ELK VM" - Hostname: ELK, running Elasticsearch, Logstash and Kibana. 
3. The attacker machine used in this scenario is the "Kali VM" - Hostname: Kali, running packetbeat.

# all virtual machines are hosted on the same virtual subnet: 192.168.1.0/24.
'

Network Diagram

<img width="1107" alt="Network Diagram" src="https://user-images.githubusercontent.com/90374994/155469759-4c85b3d2-b943-4dc6-9470-f30aff583601.png">


