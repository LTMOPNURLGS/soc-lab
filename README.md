# soc-lab
SOC Threat Emulation and Detection Lab Repository! In this repository, I’ll guide you through cyber security operations, focusing on threat emulation and detection using the MITRE ATT&amp;CK Matrix. You’ll gain hands-on experience and practical insights into how SOC (Security Operations Center) analysts detect and respond to threats.
![Poster](./misc/img-1.jpg)
The lab environment includes an OPNSense firewall, Windows Active Directory, Windows Host, an Adversary Kali Linux machine, and a Splunk instance for log collection and analysis. I’ll use Atomic Red Team for threat emulation, which allows replication of various attack techniques.
I’ll focus on 12 tactics and their corresponding techniques from the MITRE ATT&CK Matrix, each representing a different phase of an adversary’s attack life-cycle. By the end of this series, you will have a comprehensive understanding of these tactics and the ability to detect and respond to them using Splunk and Sysmon, or why not try a choice of your SIEM and EDR solution?

## What to Expect

Here’s what the repository will cover:

1. **Lab Topology and Tools Overview**: A detailed description of the lab setup. Introduction to Atomic Red Team and its role in threat emulation.
2. **Tactics and Techniques Overview**: An introduction to the MITRE ATT&CK Matrix. Highlighting techniques and their significance in the attack life-cycle.
3. **Practical Labs**: Each post will focus on a specific tactic, providing practical emulation exercises using Atomic Red Team, detection strategies with Splunk and Sysmon, and analysis of findings.

## Goals of the Repository

The primary goals are to:

- **Educate**: Provide a deep understanding of various attack tactics and techniques.
- **Practice**: Offer hands-on experience with threat emulation and detection.
- **Enhance Skills**: Improve your ability to detect and respond to threats in a SOC environment.

## Getting Started

This lab assumes a basic level of familiarity and will build on that foundation. Before diving into the practical labs, ensure you have a basic understanding of:

- **Networking**: Familiarity with network protocols and firewall configurations.
- **Operating Systems and Security Appliances**: Basic knowledge of Windows, Linux, and Active Directory as well as firewalls, EDR, and IDPS.
- **Log Analysis**: Understanding the importance of logs in threat detection and familiarity with Splunk.

## Resources

- [MITRE ATT&CK MATRIX](https://attack.mitre.org/matrices/enterprise/)
- [ATOMIC RED TEAM](https://github.com/redcanaryco/atomic-red-team)

## Importance of Practice in an Isolated SOC Lab

Practising in an isolated SOC lab environment is crucial for honing cybersecurity skills without the risks associated with a live network. This controlled setting allows you to test and refine your techniques, ensuring compliance with ethical standards and legislation. In the UK, the Computer Misuse Act 1990 outlines the legal boundaries for cybersecurity activities, and similar laws exist worldwide to promote ethical behaviour in this field.

It’s essential to understand that the complexity of your SOC lab isn’t as important as a solid foundational knowledge of Networking, TCP/IP suite, Network Devices, and Security appliances. If you can manage and secure a small-scale lab effectively, you’ll be capable of handling larger, more complex environments — albeit with increased time and resources. Remember, the more intricate a system is, the more challenging and costly it is. Also, remember that the lab components should not necessarily be the same; you can use your choice of SIEM, EDR, IDPS if you understand the concept of these exercises!

## Introduction to the Topology

The SOC lab we’ll use is designed to be as simple as possible while still covering the necessary components for effective threat emulation and detection. We won’t delve into the specifics of setting up virtual machines, as there are numerous resources available online for that purpose.

To create your lab, follow the topology and the steps below:

![Lab Topology](./misc/Topology.jpg)

1. Install the necessary machines and services, as well as Splunk Forwarders. (No extra configurations)
2. Configure network interfaces with appropriate addresses. Enable services like DHCP if needed. (No extra configurations)
3. Configure the logs to be forwarded, and you’re ready to join us.

The lab consists of the following components:

- **OPNSense Firewall**: A firewall, in simple terms, is a device or application that serves as a network traffic blockade, controlling the flow of data between networks and preventing unauthorised access. Our firewall also has Suricata installed, which is an open-source network threat detection engine that could also be configured to act as an IPS.
- **Active Directory Server**: The Active Directory Server is a centralised database of users, computers, and resources within a network.
- **Windows Host**: A Windows Host refers to a standard computer running a Windows operating system, used in the lab to simulate user activities and endpoint interactions. We will collect Windows Events and Sysmon logs from it.
- **Splunk Server**: The Splunk server is a powerful platform for searching, monitoring, and analysing machine-generated data. It collects logs from various sources and provides insights for threat detection.
- **Atomic Red Team**: Atomic Red Team is a collection of simple, practical tests to validate the detection capabilities of your security controls. It allows us to emulate adversary tactics and techniques effectively.
- **Kali Linux Host**: Linux distribution providing tons of tools for Cyber Security operations. In our case, it will serve as an Adversary.

## Importance of Logs in Threat Detection

Logs are critical for monitoring and detecting suspicious activities within your network. In our lab, we will collect logs from the following sources:

- **Firewall Logs**: Monitor incoming and outgoing network traffic, identifying potential threats and unauthorised access attempts. This includes logs from Suricata for network threat detection.
- **Windows Event Logs**: Provide detailed information about system events, user activities, and security-related incidents on Windows Hosts.
- **Sysmon Logs**: Offer detailed insights into process creations, network connections, and file changes on Windows Hosts.
- **Active Directory Logs**: Track user authentication, directory service access, and modifications within the Active Directory Server.

## Navigating the MITRE ATT&CK Matrix: Tactics and Techniques

The MITRE ATT&CK is a comprehensive framework that categorises the various tactics and techniques used by adversaries during cyber attacks. Understanding this framework is essential for identifying and mitigating threats. You can explore the full matrix and detailed descriptions of each tactic and technique on the official MITRE ATT&CK website.

![MITRE ATT&CK](./misc/MITREATT&CK.jpg)

[MITRE ATT&CK Website](https://attack.mitre.org/)

## Next Steps

Now that we’ve covered the basics of our SOC lab topology, tools, and the MITRE ATT&CK framework, it's time to dive into our first exercise. Head over to MITRE_Emulation_Detection to get started. We will emulate our first techniques within "TA0002 Execution" and try to detect them.

