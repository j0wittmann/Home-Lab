# Cyber Security Home Lab

## Foreword

All network components can be provided as a VirtualBox .ova image for easy deployment. If you are interested or need access, feel free to reach out to me on LinkedIn. You can find the link to my LinkedIn profile on my GitHub profile.

## **Abstract**

This project focuses on the design and implementation of a secure network management system using VirtualBox to simulate a complex network environment.
A given network range is divided into multiple segments, all connected to the WAN through a next-generation, two-stage pfSense firewall.
The network includes segments for servers, clients, a DMZ, a secure LAN, and a lab environment with several routers.
The goal is to establish a secure network configuration using VLANs and various monitoring tools.
Reconnaissance and other types of attacks originating from both inside and outside the network are detected and mitigated.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/Network%20Plan.png" alt="Network Plan" width="700">
</div>

# **1. Introduction**
For network segmentation, /26 subnets are used to provide sufficient IP addresses for current and future devices.
The DMZ and Secure LAN segment are intentionally configured as /28 subnets, as they require fewer hosts and thus fewer IP addresses.
This allocation leaves the 192.168.10.160/27 range unused, serving as a flexible reserve for future expansions.

The network is protected by a next-generation pfSense firewall, which acts as the primary gateway and shields the internal infrastructure from both external and internal threats.
It is connected to the WAN, allowing controlled communication between the internal network and the Internet.
A WAN router forwards traffic from the Internet to the firewall and routes internal traffic back out.

Additionally, a second pfSense firewall is deployed within the internal network to create the Secure LAN segment. This two-stage firewall setup enhances network isolation and ensures that sensitive resources are protected from unauthorized access, even within the internal network.

Some network segments are configured with VLANs, further increasing security by isolating traffic and making lateral movement more difficult for potential attackers.

To monitor the network, OpenNMS is used to check host and service availability, while Splunk serves as a SIEM for detecting unusual activity.
The pfSense firewall filters traffic based on defined rules, and Snort is deployed as an IDS/IPS to detect and block potential threats.

Within the DMZ, an OWASP Broken Web Applications server is deployed as a target for simulated attacks. Additionally, DVWA (Damn Vulnerable Web Application) is hosted in the DMZ as an insecure web application.
In the SERVERS segment, a Metasploitable 3 server is deployed to provide further vulnerable services for exploitation and offensive security testing.

The network includes both an internal attacker (located in the client segment) and an external attacker (outside the network), which are used for offensive security testing. These attacker nodes help simulate real-world threat scenarios, allowing for the identification of vulnerabilities and evaluation of defense mechanisms.

All these victim systems are intentionally misconfigured or vulnerable, providing a safe environment to practice exploitation techniques and test security tools.

In the lab segment, VyOS routers are configured to simulate and practice routing scenarios.

# **2. Configuration**
## 2.1 Configuring the interfaces

To ensure proper network functionality, all interfaces of the respective systems are configured according to the network plan:
- The Kali hosts and the web server are configured by editing the ‘/etc/network/interfaces’ file
- The VyOS routers are configured using the configure command
- The OpenNMS and Splunk servers are configured using netplan
- The Windows 10 host is configured through the Windows network settings
- Both pfSense firewalls are configured via the web interface

## 2.2 Routing

The pfSense firewall acts as the default gateway for each segment within the network. Since the firewall is directly connected to all segments, communication (e.g., pinging) between them is possible. To reach subnets that are not directly connected to the firewall, appropriate gateways and static routes must be configured.
In order to access the WAN and to make the web server reachable from the Internet, static routes must be configured on the WAN router.
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/WAN%20router%20static%20routes.png" alt="WAN router static routes" width="250">
</div>

## 2.3 Port Forwarding
An OWASP Broken Web Applications server is deployed in the DMZ. To make this server accessible from the WAN, port forwarding is configured via the pfSense web interface.
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/Port%20Forwarding.png" alt="Port Forwarding to webserver" width="700">
</div>
As a result, the web server is now accessible via the WAN IP of the pfSense1 firewall. The NAT table translates incoming requests to the internal IP address of the web server.

## 2.4 pfSense two-staged firewall
A two-stage firewall setup has been configured. The primary firewall, pfSense1, protects the internal network from the WAN and routes traffic between network segments based on defined rules. In addition, a secondary firewall, pfSense2, is deployed within the internal network to protect the so-called “Secure LAN”.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/Initiate%20Connections.png" alt="pfSense1 Initiate Connections" width="600">
</div>

pfSense is a next-generation, stateful firewall. Firewall rules are applied on the interface where packets enter pfSense. It tracks the state of each connection, allowing legitimate return traffic automatically.
A whitelisting approach is used, where all traffic is blocked by default and only explicitly allowed connections are permitted.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/pfSense1%20Clients%20Interface.png" alt="pfSense1 Clients Interface rules" width="700">
</div>

The screenshot shows the firewall rules configured on the CLIENTS interface.
These rules allow the Kali (SNM) client to access and configure the pfSense firewall, Splunk and OpenNMS via their respective web interfaces.
In addition, all clients are permitted to access the OWASP web server via HTTP on port 80.
Access to the rest of the internal network is explicitly blocked.
However, clients are allowed to connect to the Internet, which is made possible by the second-to-last rule that permits outbound traffic while still enforcing internal network isolation.

## 2.5 OpenNMS and SNMPv3
For network monitoring, OpenNMS is used in combination with SNMPv3.
This version of SNMP offers enhanced security features such as authentication, encryption, and message integrity, providing a more secure and reliable network management solution. The discovery process for the network was configured via the OpenNMS web interface.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/OpenNMS%20Discovery.png" alt="OpenNMS Discovery" width="700">
</div>

The OpenNMS server actively scans the network by sending ICMP Echo Requests to potential hosts.
If a host replies with an ICMP Echo Reply, OpenNMS recognizes the host as active and reachable.
This mechanism is used during the discovery phase to identify which devices are online and can be monitored.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/OpenNMS%20Overview.png" alt="OpenNMS Overview" width="650">
</div>

The captured traffic shows that SNMPv3 is being used for communication.
With SNMPv3, the Protocol Data Unit (PDU) is encrypted, ensuring that sensitive information, such as credentials or monitoring data, remains confidential.
This encryption effectively protects the communication from being intercepted and read by a Man-in-the-Middle (MitM) attacker, even if the traffic is captured.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/SNMPv3%20get-request.png" alt="SNMPv3 get-request" width="750">
</div>

## 2.6 Snort
Snort is an IDS/IPS system and can be enabled by installing it via the pfSense Package Manager.
<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/Snort%20Interfaces.png" alt="Snort Interfaces" width="600">
</div>
Rules are applied to the selected interfaces.  

When a rule is triggered, Snort generates an alert, which is then logged and displayed in the alert view.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/Snort%20Alerts.png" alt="Snort Alerts" width="600">
</div>

If Inline IPS mode is enabled, Snort does not only detect and alert, but can also actively reject or drop malicious packets.
In this mode, Snort operates as an Intrusion Prevention System (IPS) rather than just an Intrusion Detection System (IDS), providing real-time protection by preventing attacks before they reach their target.

## 2.7 Splunk
Splunk is a Security Information and Event Management (SIEM) platform that collects, analyzes, and visualizes log data to detect security threats and operational issues.

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/Splunk%20Alerts.png" alt="Splunk Alerts" width="800">
</div>

Using SPL (Search Processing Language), custom detection rules can be defined in Splunk.
When the conditions of a rule are met, such as a specific number of suspicious packets, an alert is automatically triggered.
This alert can then notify the SOC (Security Operations Center) team, enabling them to respond to potential threats in real time.  

<div align="center">
    <img src="https://github.com/j0wittmann/Home-Lab/blob/main/screenshots/Splunk%20UDP%20Flood.png" alt="Splunk UDP Flood search" width="900">
</div>
