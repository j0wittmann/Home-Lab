# Network Security Home Lab

## Foreword

All network components can be provided as a VirtualBox .ova image for easy deployment. If you are interested or need access, feel free to reach out to me on LinkedIn. You can find the link to my LinkedIn profile on my GitHub profile.

## **Abstract**

This project focuses on designing and implementing a secure network management system using VirtualBox to simulate a complex network environment. A given network range is divided into multiple segments, which are connected to the WAN through a next-generation two-staged pfSense firewall. There are segments for servers, clients, a DMZ with a web server, a secure LAN area and a lab segment with several routers. The goal is to setup a secure network configuration while working with VLANs and various monitoring tools. There are reconnaissance and other attacks from inside and outside the network which will be recognized and defended.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/Network%20Plan.png" alt="Network Plan" width="700">
</div>

## **1. Introduction**
For the segmentation I decided to use /26 subnets to provide sufficient IP addresses for current and potential future devices. The DMZ and secure LAN segments were intentionally configured as /28 subnets as these segments require fewer hosts and do not need as many IP addresses. This allocation leaves the network range 192.168.10.160/27 unused, providing a flexible reserve for potential future expansions. The network is secured by a pfSense next-generation firewall, which acts as the primary gateway and protects the internal network from external and internal threats. This firewall is connected to the WAN, allowing controlled communication between the internal network and the internet. A WAN router forwards traffic from the internet to the firewall and routes internal traffic back to the internet. Additionally, a second pfSense firewall within the network creates the secure LAN segment, providing an additional layer of security. This two-staged firewall setup enhances network isolation and ensures that sensitive resources in the secure LAN are protected from unauthorized access, even within the internal network. Some network segments are configured with VLAN, this setup makes the network more secure and harder for attackers to access other parts of the network. The network is monitored using tools like OpenNMS to check the availability of hosts and services, and Splunk as a SIEM to detect unusual activity. The pfSense firewall filters traffic depending on the configured rules, and SNORT is set up on the firewall as an IDS/IPS to detect and block threats. In the DMZ, an OWASP Broken Web Application Server is deployed, which serves as a target for attacks. The network also includes an internal attacker located in the client segment and an external attacker outside the network, both used to attack the network as part of offensive security testing. These attackers help simulate real-world scenarios, allowing for the identification of vulnerabilities and the evaluation of defensive measures. In the lab segment VyOS routers are configured to practice and simulate routing scenarios.

## **2. Configuration**
### 2.1 Configuring the interfaces

To make the network function properly all interfaces of all entities are configured according to the Network Plan:
- The Kali hosts and the webserver are configured by editing the ‘/etc/network/interfaces’ file
- The VyOS routers are configured by editing the routers with the ‘configure’ command
- The OpenNMS and Splunk servers are configured with netplan
- The Windows 10 host is configured over the Windows settings
- Both pfSense firewalls are configured by the web interface

### 2.2 Routing

The pfSense firewall acts as the default gateway for every segment within the network. Since the firewall is directly connected to the segments, it is possible to ping between them. To ping subnets that are not directly connected to the firewall, gateways and static routes must be configured.
For accessing the WAN and making the web server accessible from the Internet, static routes must be configured on the WAN router.  
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/WAN%20router%20static%20routes.png" alt="WAN router static routes" width="250">
</div>

### 2.3 Port Forwarding
An OWASP broken web application server is deployed in the DMZ. This server must be reachable from the WAN. Therefore, I use port forwarding, which can easily be configured via the pfSense web interface.
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/Port%20Forwarding.png" alt="Port Forwarding to webserver" width="700">
</div>
Now, the web server is accessible via the WAN IP of the pfSense1 firewall, and the NAT table translates the requests to the internal IP of the web server.

### 2.4 pfSense two-staged firewall
I configured a two-staged firewall setup. This means that there is a main firewall, pfSense1, which protects the internal network from the WAN and routes traffic between the segments based on the configured rules. Additionally, there is another firewall, pfSense2, within the internal network to protect the so-called “Secure” LAN area.
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/Initiate%20Connections.png" alt="pfSense1 Initiate Connections" width="600">
</div>
pfSense is a next-generation, stateful firewall. The rules are applied to the interface where packets enter pfSense, and the firewall tracks the state of connections to allow legitimate return traffic.
I follow the principle of whitelisting, meaning that all traffic is blocked by default, and only the necessary connections are allowed.

### 2.5 OpenNMS and SNMPv3
For network monitoring, I decided to use OpenNMS with SNMPv3. This version of SNMP provides enhanced security features, including authentication, encryption, and message integrity, ensuring a more secure and reliable network management solution.  
In the OpenNMS web interface, I configured the discovery process for my network.
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/OpenNMS%20Overview.png" alt="OpenNMS Overview" width="650">
</div>

### 2.6 Snort
Snort is an IDS/IPS system and can be enabled by installing it via the pfSense Package Manager.
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/Snort%20Interfaces.png" alt="Snort Interfaces" width="600">
</div>

### 2.7 Splunk
Splunk is a Security Information and Event Management (SIEM) platform that collects, analyzes, and visualizes log data to detect security threats and operational issues.
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/Splunk%20Alerts.png" alt="Splunk Alerts" width="800">
</div>
