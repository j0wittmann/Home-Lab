# Network Security Home Lab

## **Abstract**

This project focuses on designing and implementing a secure network management system using VirtualBox to simulate a complex network environment. A given network range is divided into multiple segments, which are connected to the WAN through a next-generation two-staged pfSense firewall. There are segments for servers, clients, a DMZ with a web server, a secure LAN area and a lab segment with several routers. The goal is to setup a secure network configuration while working with VLANs and various monitoring tools. There are reconnaissance and other attacks from inside and outside the network which will be recognized and defended.

![Network Plan](https://github.com/j0wittmann/Home-Lab/blob/main/Network%20Plan.png?raw=true)

## **1. Introduction**
For the segmentation I decided to use /26 subnets to provide sufficient IP addresses for current and potential future devices. The DMZ and secure LAN segments were intentionally configured as /28 subnets as these segments require fewer hosts and do not need as many IP addresses. This allocation leaves the network range 192.168.10.160/27 unused, providing a flexible reserve for potential future expansions. The network is secured by a pfSense next-generation firewall, which acts as the primary gateway and protects the internal network from external and internal threats. This firewall is connected to the WAN, allowing controlled communication between the internal network and the internet. A WAN router forwards traffic from the internet to the firewall and routes internal traffic back to the internet. Additionally, a second pfSense firewall within the network creates the secure LAN segment, providing an additional layer of security. This two-staged firewall setup enhances network isolation and ensures that sensitive resources in the secure LAN are protected from unauthorized access, even within the internal network. Some network segments are configured with VLAN, this setup makes the network more secure and harder for attackers to access other parts of the network. The network is monitored using tools like OpenNMS to check the availability of hosts and services, and Splunk as a SIEM to detect unusual activity. The pfSense firewall filters traffic depending on the configured rules, and SNORT is set up on the firewall as an IDS/IPS to detect and block threats. In the DMZ, an OWASP Broken Web Application Server is deployed, which serves as a target for attacks. The network also includes an internal attacker located in the client segment and an external attacker outside the network, both used to attack the network as part of offensive security testing. These attackers help simulate real-world scenarios, allowing for the identification of vulnerabilities and the evaluation of defensive measures. In the lab segment VyOS routers are configured to practice and simulate routing scenarios.

## **2. Configuration**
### 2.1 Configuring the interfaces

To make the network function properly all interfaces of all subjects are configured according to the Network Plan:
- The Kali hosts and the webserver are configured by editing the ‘/etc/network/interfaces’ file
- The VyOS routers are configured by editing the routers with the ‘configure’ command
- The OpenNMS and Splunk servers are configured with netplan
- The Windows 10 host is configured over the Windows settings
- Both pfSense firewalls are configured by the web interface

### 2.2 Routing

The pfSense firewall acts as default gateway for every segment within the network. Since the firewall is directly connected to the segments it is possible to ping between the segments. For pinging subnets which are not directly connected to the firewall the gateways and static routes must be configured.
For accessing the WAN and make the webserver access able from the Internet the WAN Router static routes must be configured.

### 2.3 Port Forwarding
In the DMZ is an OWASP broken web application server deployed. This server must be accessible from the WAN. Therefore, I use port forwarding. This can easily be configured over the pfSense web interface.
![Port Forwarding](https://github.com/j0wittmann/Home-Lab/blob/main/PortForwarding.png?raw=true)  
Now the webserver is access able over the WAN IP from the pfSense1 firewall and the NAT table translates the requests to the internal IP of the webserver.
