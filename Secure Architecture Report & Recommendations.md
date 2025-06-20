# 

# Secure Architecture Report & Recommendations

Christian Barratt  
Lighthouse Labs

### Table of Contents

[**1 \- Introduction**](#1---introduction)

[**2 \- Current Security Landscape**](#2---current-security-landscape)

[**3 \- Security Architecture Goals**](#3---security-architecture-goals)

[**4 \- Security Architecture Recommendations**](#4---security-architecture-recommendations)

[**5 \- Implementation Strategy**](#5---implementation-strategy)

[**6 \- Summary of Findings**](#6---summary-of-findings)

[**References**](#references)

### 1 \- Introduction

The following report was created as a comprehensive summarization of the current state of the security landscape in a mid-sized, e-commerce company that has undergone a full-scale end-to-end security architecture assessment. Security architecture, as defined by the National Institute of Standards and Technology (referred to as NIST from here on) is:  
A set of physical and logical security-relevant representations (i.e., views) of system architecture that conveys information about how the system is partitioned into security domains and makes use of security-relevant elements to enforce security policies within and between security domains based on how data and information must be protected. (NIST SP 800-37 Rev. 2\)  
It will highlight notable areas and assets in need of additional security measures in order to comply with suggested mitigation strategies, as per the standards and policies provided by NIST. These mitigation strategies are meant to minimize risk to company standard operations, some suggested strategies include but are not limited to: the protection of employee and customer data, the implementation of network monitoring and intrusion detections systems, the segmentation of overall network architecture, and improving security of the private payment network through the use of Virtual Private Network (VPN) services. To note: The author of this report has provided these mitigation strategies (discussed below in section 4 \- Recommendations) without knowledge or proper consideration of the company’s resources and budget constraints. Therefore, some suggested mitigation strategies provided in the following report may not be viable options and therefore may need revisions or alternatives.

### 2 \- Current Security Landscape {#2---current-security-landscape}

In this section we cover the vulnerabilities and risks found during the end-to-end security architecture assessment in regards to the security architecture currently being utilized by the company. Please note that the following list will cover key areas in need of an improved security posture, rather than a full list of all items/assets identified within the initial assessment report.

1. **Flat Network Architecture**  
   The company utilizes a flat network architecture, meaning there is no designated segment within that acts as an intermediary between the internal network and the internet. All devices that connect to a single switch or hub can communicate with each other without intermediaries. As a result, they all have the same level of access due to their classification as “peer” devices (Tripathy, 2023).   
   Additionally, by utilizing a flat network architecture the internal network systems rely heavily on switches and other access points, these filters are connected to numerous devices within the organization. These systems and devices include employee workstations, laptops, printers and other. This also holds true to the company’s wireless network provided to both employee and guest alike. This situation is a cause for concern due to the current implementation of a simplistic combination of username and password policy within the internal network system and devices, a policy that is shared with the wireless network.  
   1. *Vulnerabilities and Risks*:  
      1. Prone to Lateral Attacks: all switches and hosts receive the same network traffic, meaning sensitive data may end up being shared with everyone on the network. This vulnerability can also be used by attackers to quickly spread malicious payloads throughout the system, (i.e. Ransomware). \[TA-0008\], \[SI-14\]\[AC-5\]\[AC-6\]  
      2. Insecure / weak password policy   
         1. Credential Access \[TA0006\]: Simple usernames and passwords can be guessed or brute forced, allowing access to the network. \[T1110\]  
         2. Password Policy Discovery \[T1201\]  
      3. No DHCP Snooping \[T1557.003\] implemented on networked devices (internal and wireless):   
         1. IP Spoofing   
         2. Man-in-the-Middle attacks  
         3. Denial-of-service attacks (DoS).  
      4. Taint Shared Content \[T1080\]: Adversaries may deliver payloads to shared storage locations, such as network drives  
      5. Persistence: Increase in bandwidth communication makes it easier for hackers to remain hidden within the network. \[MITRE, TA0003\], \[SI-14\]  
      6. Difficulty in Troubleshooting: Because there is no segmentation within the network, finding the root cause of problems that occur can be difficult. \[AC-3\]\[SI-11\]  
      7. Lack of Redundancy: Current dependence on single switches can cause the network to fail or halt, as there is no alternative path for it to take. \[CP-2\]\[SI-13\]\[AC-4\]  
      8. Trust Relationship \[T1199\]: All devices are linked through switches and access points with no intermediary, if an adversary gets in they will potentially have access to all shared data between those devices.  
      9. Flat networks avoid using Layer 3 routing, therefore removing traditional security technology such as firewalls, filters and other security appliances (NetworkComputing, 2019). \[AC-1\]\[AC-3\]  
      10. Input Capture \[T1056\]: users may have their credentials or collected information captured by means of deception, providing input into a seemingly legitimate service (e.g. Web Portal Capture).   
          1. Keylogging \[T1056.001\], depending on where an employee connects to wifi via a mobile device, credentials may be acquired  or leaked.  
      11. Wireless Compromise \[T0860\]: there is no intermediary between the wifi accessed router and internal network systems, all network devices are connected through a single Virtual local area network (VLAN).

            
2. **Network Monitoring and Security Devices**  
   The company was found to be lacking any form of effective network monitoring or intrusion detection system. This vulnerability presents a critical risk to the company’s systems, as it allows for potential security incidents to go unnoticed. (i.e., attackers, in the event of an intrusion, can remain undetected within the system, resulting in a loss of data confidentiality, integrity and potentially availability).  
   1. *Vulnerabilities and Risks*:  
      1. Persistence: the lack of effective means in detecting security incidents makes it easier for malicious variables to remain hidden within the network. \[MITRE, TA0003\], \[SI-14\].   
      2. No DHCP Snooping implemented: can lead to IP Spoofing, Man-in-the-Middle attacks, Denial-of-service attacks (DoS).  
      3. Active Scanning \[T1595\], network may be prone to probing reconnaissance attempts.  
      4. Compliance Issues: regarding potential rules and regulations required by rules and regulations of the industry (i.e. Personal Information Protection and Electronic Documents Act, (PIPEDA)).  
      5. This can lead to a compromise of data Confidentiality, Integrity, and Availability:  \[SI\] family, System and Information Integrity

3. **Employee Workstations**  
   Employee devices were found to have Antivirus software present however, it is not updated to the latest patch nor does it have a regularly scheduled plan implemented to do so.  
   1. *Vulnerabilities and Risks*:  
      1. Impair Defenses \[T1562\]: Outdated endpoint security solutions, in this case the firewall for employee devices, can be exploited by adversaries thereby leading to compromise in employee and workplace intellectual property.   
      2. Downgrade Attack \[T1562.010\]: adversary may downgrade or use a system feature that is outdated to compromise the network and systems.  
      3. Disable or Modify System Firewall \[T1562.004\]: adversary may modify the firewall to bypass controls limiting network access, or compromise rule sets. (i.e. edit Registry keys, utilize the command line, access Windows Control Panel)  
      4. Phishing \[T1566\]: Outdated firewall may not account for newer applications of phishing attempts via suspicious link or service.

4. **Servers**  
   Company web server hosts public-facing services such as the e-commerce website and payment gateways. The company also allows external users to interact with these services. Company web server is responsible for serving web pages, processing online orders, and managing customer accounts. This is a cause for concern due to the web server also being the means in which the payment gateway service (further referred to as PGS) is deployed and utilized. The PGS transmits packets of information through an external address (76.71.1.105/28), which is a public IP address. Meaning, it can be used as an attack vector for adversaries (i.e. reconnaissance, man-in-the-middle, drive-by compromise).  
   1. *Vulnerabilities and Risks:*  
      1. Exploitation of Public-Facing Applications \[T1190\]: Adversaries can make attempts to exploit weaknesses in an Internet-facing host or system (i.e. Web Server)  
      2. Exploitation for Defense Evasion \[T1211\]: Vulnerabilities found in existing systems or applications may be used to bypass security features.  
      3. Credential Access \[TA0006\]: Compromised web server can lead to compromised user credentials \[T1555.003\]  
      4. Compromised accounts can lead to a loss of customer data Confidentiality.  
      5. Financial Theft \[T1657\]: adversaries may steal monetary resources through social engineering, technical theft or other methods. Compromised accounts may conduct unauthorized transfers of funds.  
      6. Gather Victim Identity Information \[T1589\]: Adversaries may gather information about the victim's identity.  
      7. Exploitation of Public Facing Application \[T1190\]  
      8. Drive-by Compromise \[T1189\]  
      9. Adversary-in-the-Middle \[T1557\], adversaries may utilize the fact that the payment service transfers data over a public IP address. They may act as a man-in-the-middle to acquire customer financial information and records, by intercepting the data packets in transit or eavesdropping on network traffic. \[SI-18\]  
      10. Credentials from Password Stores \[T1555\] \[AC-3\], current centralized implementation of servers (web, database, certificate) can be compromised all at once by adversaries.   
      11. Compromised Payment systems can lead to loss in customer data  Confidentiality, and Integrity.

### 3 \- Security Architecture Goals {#3---security-architecture-goals}

With the expected growth of the organization, a need for increased security measures becomes a worthwhile venture. On average, enterprises use more than 130 security tools-tools that only create more challenges to manage, require a larger workforce and demand a significant portion of the security budget (Ariganello, 2022). A Security architecture provides a vital foundation for a successful cybersecurity strategy, it allows security architects to establish a strong and adaptable security posture within an organization.  
From a business standpoint, a security architecture can be utilized to ensure adherence to specific industry-standards and regulations (i.e. NIST, and International Organization for Standardization (ISO) standard). Additionally, because security architecture employs zero trust, and privacy-by-design principles, enterprises are able to meet industry regulations and compliance requirements (i.e., data protection, access controls and privacy) with relative cost and time-consuming ease (Arora, 2023). That being said, in order for organizations to meet their security needs, security leaders (i.e. Chief Information Security Officers (CISO)) will need to develop security architecture programs that covers a series of steps, as such listed below:

1. Understanding business goals and IT security requirements  
2. Identify threats, attack vectors and vulnerabilities  
3. Select industry-recognized security architecture frameworks or create a custom one to fit specific industry/organizational needs.  
4. Identify security controls and technologies  
5. Define and document physical, logical and conceptual architectures  
6. Monitor, improve, govern and align with evolving business and technical needs.

### 4 \- Security Architecture Recommendations {#4---security-architecture-recommendations}

This section will cover various means of mitigation (in regards to the vulnerabilities reported in section 2 of this report), as recommended by the Mitre Att\&ck framework on tactics and techniques of known vulnerabilities. 

1. **Flat Network Architecture**  
   With the company growing in operation size, it is no longer viable to utilize solely a Flat Network Architecture. Flat networks in big organizations with a large number of users, creates a lot of “noise” along the broadcast domain (Tripathy, 2023). This results in excessive amounts of unnecessary traffic which can prove to be rather chaotic when trying to diagnose a problem. One way to account for this flaw is to implement a defense-in-depth (DiD) strategy in order to protect the network from cyberattacks.   
   1. Network Segmentation \[M1030\]: Isolating more critical systems, functions and resources through the use of either physical or logical means, in order to prevent unauthorized access to sensitive systems and information. For example:  
      1. Segmenting outward-facing systems from internal systems (i.e. the Web Server, which hosts the company’s website and payment gateway service). \[SC-5\]   
      2. Separation of wireless network from internal systems via the use of firewall, configured to only allowing ports 80 and 443 for traffic flow \[DS0018\] \[SC-3\]  
   2. Restrict File and Directory Permissions \[M1022\]: Implement restrictive configuration on directory and file permissions, so that users cannot access parts of the network they are not authorized to do so (i.e. database server). \[T1552.001\] \[SC-4\]  
   3. Implement Redundancy \[M0811\], in the event of compromise from sources such as Denial of Control \[T0813\], Loss of Availability \[T0826\], Change in Credential \[T0892\], redundancy systems can replace compromised assets in order to ensure critical operations still function.  
   4. Require Stronger Passwords \[M1027\]:  Set and enforce secure password policies for employee and customer accounts.  
      1. Combat Forced Authentication \[T1187\] by increasing the difficulty of cracking credential hashes should they be obtained.

      

2. **Network Monitoring and Security Devices**  
   By failing to implement any form of effective network monitoring or intrusion detection system, the company has failed to comply with the latest industry requirements for standards in regards to the rules and regulations of e-commerce / commercial network compliance (HIPAA, PIPEDA, etc.). Meaning, unless the company rectifies this matter they are liable to suffer hefty penalties imposed by regulators or government due to the infringement of various industry standards and regulations, such as Sarbanes-Oxley Act (SOX) and DISA STIG. (SolarWings, 2024\)  
   1. Automated configuration management:  
      1. Execution Prevention \[M1038\], using application controls to mitigate the installation and use of payloads that may be used to spoof security alerts. \[SI-16\]\[AC-25\]  
   2. Proactive monitoring: anticipating issues that can be addressed before an application crashes or performance degradation sets in.  
      1. Establish communication with developers, IT professionals, and stakeholders to identify a baseline for “normal” business operation.  
   3. Compliance documentation:  
      1. Audits \[M1047\]: Having detailed audit-ready reports that must be passed regularly \[AU-6\], can be beneficial to the organization’s continuous monitoring, contingency planning, incident response, investigation and response to suspicious activities. \[PM-7\] \[AU-12\] \[IR-4\]  
         1. Enable security auditing to collect logs for monitoring network traffic and events. \[DS0015\]  
      2. Create Incident Response policies and procedures \[IR-1\] \[IR-2\] \[IR-6\]  
         1. Incident Handling \[IR-4\]: Coordinate incident handling activities with contingency planning activities; incorporating lessons learned from ongoing incident handling activities into response procedures, training and testing;   
         2. Incident Monitoring \[IR-5\]: Tracking and documenting incidents, maintaining records of each incident, the status of the incident and other relevant information necessary for forensic evaluation.  
   4. Implement Dynamic Host Configuration Protocol (DHCP) Snooping security features on VLAN interfaces. \[IA-3\] \[AU-2\]  
      1. Rate-limits for DHCP traffic from trusted and untrusted sources (for example, employee and guest connections to wifi network).  
      2. Validate DHCP messages received from untrusted sources and filter out invalid messages. \[AC-3\] \[CM-6\]  
         

3. **Employee Workstations**  
   Mitigations towards employee workstations are meant to further improve upon the security implementations already being utilized within the organization. (ie. endpoint security solutions, such as antivirus software). This is a particularly important avenue to address due to reports from a number of studies that suggest that 95% of cybersecurity issues can be traced to human error (World Economic Forum, 2020).  
   1. Practice Regular Patch Management: Security updates and software should be regularly patched to ensure the best possible protection from malicious activity within the network.  
      1. Keep Antivirus/Antimalware \[M1049\] software up-to-date: This will give the software access to the latest libraries of known vulnerabilities, allowing the software to automatically quarantine suspicious files. This can also help prevent incidents involving phishing attacks, thereby reducing the risk of human interaction.  
   2. Limit User Permissions: Set up access restrictions within an active directory to protect both workstation and the network (i.e. create a policy of least privilege to limit user account access on an as-needed basis). \[AC-2\] \[AC-6\]

4. **Servers**  
   Currently, the organization makes use of a centralized server system which contains all data pertaining to: stored customer information, including personal details and purchase history (Database Server); internal business records, the e-commerce website, and the facilitation of customer online orders and accounts (Web Server);   
   This configuration presents a number of problems, one of note is the potential complete compromise of all network data in the event of a security incident. With all information being stored in one location, adversaries will not need to circumvent obstacles in order to gain access to the stored data, thereby compromising its confidentiality, integrity and potentially availability. This could result in a total loss of control over business operations, which could affect public trust and create financial repercussions.   
   1. Implement the use of a Virtual Private Network (VPN) services \[A0011\]  
      1. The web server hosts the payment gateway service, which as to date utilizes a public IP network to transfer packets to and from the web server. Utilizing a VPN service will help to mask that traffic, thereby allowing it to adhere to NIST policies for System and Communications Protection. \[T0830\] \[T0866\] \[T0888\] \[SC-1\]   
      2. Boundary Protection \[SC-7\] can be used in the event of suspected compromise due to suspicious traffic being made.  
   2. Creating a Demilitarized Zone (DMZ) for outward facing Web Server. \[SC-7\]  
      1. Implementing the use of firewalls specifically configured to segment the Web Server from the internal system databases.    
   3. If web server connection is needed for internal use, consider implementing an additional Internal Web Server in order to create an Intranet zone. Load balancers can be implemented to distribute the processing load. (Oracle, 2016\)  
   4. Database Encryption at Rest and in Transit: To counteract the current network architecture, all database connections using the Transport Layer Security (TLS) protocol should be encrypted while in transit. Encryption can also be applied to disks containing stored data, such as the Database Server.   
      1. File Modification \[DS0022\] detection systems should be in place to help identify incidents of system feature abuse. Encryption based attacks are hard to mitigate with preventive controls (MITRE, \[T1600\], 2020).  
   5. Revoke Privileges Continuously \[AC-2\]: When access to privileged roles or attributes are no longer appropriate or required, revoke access.  
   6. Implement Identity and Access Management (IAM) practices \[IA-5\]: Adversaries may modify authentication mechanisms and processes to access user credentials and accounts.  
      1. Applying Multi-factor Authentication \[M1032\] can greatly reduce the risk of an adversary gaining control of valid user credentials that may be utilized for additional tactics such as: initial access, lateral movement and information collection.  
      2. Authorization Enforcement \[M0800\]: systems and devices should restrict read, manipulate or execute privileges to authenticated users based on approved security policies.  
         1. Role-based Access control (RBAC) \[AC-3\]

            

### 5 \- Implementation Strategy {#5---implementation-strategy}

The following section will highlight a proposed phase approach to implementing the recommended security measures documented within the previous sections of this report. The proposal is designed to be implemented over a course of one year, broken down into quadrimestre (every 4 months) segments. Ideally this will help ease employees and customers into the new processes and policies to be implemented throughout the organization.

1. Phase 1 (First Quarter: Jan 2024, April2024)  
   1. Establish communications with stakeholders on garnering approval of proposed network security updates.  
   2. Establish communications between developers, IT professionals and stakeholders to establish a baseline of “normal” business operations.  
   3. Implementation of DHCP services to current networked devices.  
   4. Implement minimum requirements of monitoring and intrusion detection systems required per industry standard.  
   5. Encrypt network traffic between Payment Gateway service and Web Server via the use of Virtual Private Network (VPN).  
   6. Segment Web Server from Network via the use of firewalls to create a Demilitarized zone.  
   7. Roll out first series of Access Controls:   
      1. Role-based Access Control on employee devices and workstations, and servers  
      2. Implement encryption of data at rest and in transit to the database server.  
      3. Update password and username policy (Internal Network resources and Wireless Network)  
      4. Notify Users (Customers) of change in user password and username policy to be implemented at a later date.

2. Phase 2 (May 2024, August 2024\)  
   1. Rollout updated password policy to customers and users  
      1. Including Multi-Factor Authentication (MFA)   
   2. Improve upon network monitoring systems and intrusion detection systems to fall more inline with industry standards and organization requirements.  
   3. Perform segmentation of internal networks from public facing devices, such as ISP connection and wireless networks.  
      1. Update firewall configurations to filter out unwarranted traffic to or from unauthorized ports.  
      2. Implement an additional database server in response to increased customer base. Apply necessary configurations for security in compliance to NIST standards.

3. Phase 3 (Sept 2024, Dec 2024\)  
   1. Finalize segmentation process of network architecture.   
      1. Internet Zone: including ISP, Cloud storage service, wireless network (external web and mobile client), and Private Payment network (traffic funneled through VPN service)  
      2. Demilitarized Zone: including Web Server, external firewall (for internet) and internal firewall (web server to internal network)  
   2. Roll out the latest update to Intrusion Detection and Network Monitoring systems, specifically tailored for company requirements and needs.

### 6 \- Summary of Findings {#6---summary-of-findings}

With the ever changing nature of the internet and subsequently the cybersecurity field, there is no shortage of cyber threats and malicious actors. It becomes ever apparent that organizations have the need to invest into advanced security tools in order to combat these ongoing threats. A comprehensive security architecture serves as a form of defense that takes a proactive role in identifying, assessing, and prioritizing risk-based security strategies. In regards to this report, we have gone over a series of network security recommendations to help protect the organization and its assets. Included but not limited to: the integration of network monitoring tools and services, identity and access management (IAM), data protection through the use of encryption, and application security via the use of firewalls and segmentation of outward facing facilities (i.e. Web Server).  
Had these recommendations not been proposed, the current state of the network would not be able to handle the increase flow of traffic, as a result of customer base expansion, nor would it have been effective in its ability to monitor and diagnose said traffic, due to the network currently lacking any means of effectively doing so (i.e. lack of network monitoring and intrusion detection systems). Additionally, in the event of a compromise, should a malicious actor gain access to the centralized database, the adversary could cause irreparable damage to customer and employee trust, organization reputational damage, or even potentially cause severe financial loss. Said loss could be compounded upon, should authorized officials perform an audit of non-existent security measures that may be required by federal rules and regulations / industry standard.

### References {#references}

Techniques \- Enterprise | MITRE ATT\&CK®. [https://attack.mitre.org/techniques/enterprise/](https://attack.mitre.org/techniques/enterprise/).

National Institute of Standards and Technology. (September 2020). NIST Special Publication 800-53 Revision 5\. [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) 

Tripathy, S. (2023, February 21). *What Is a Flat Network?* Enterprise Networking Planet. [https://www.enterprisenetworkingplanet.com/management/the-risks-and-rewards-of-flat-networks/](https://www.enterprisenetworkingplanet.com/management/the-risks-and-rewards-of-flat-networks/)

NetworkComputing (2012, March 22). *Flat Network Strength Also A Security Weakness*. Network Computing. Retrieved January 10, 2019, from [https://www.networkcomputing.com/networking/flat-network-strength-also-security-weakness](https://www.networkcomputing.com/networking/flat-network-strength-also-security-weakness) 

What is SOX (Sarbanes-Oxley Act) Compliance ? | IBM. [https://www.ibm.com/topics/sox-compliance](https://www.ibm.com/topics/sox-compliance).

Understanding DISA STIG Compliance Requirements | SolarWinds. IT Management Software and Observability Platform. [https://www.solarwinds.com/public-sector/disa-stig-compliance](https://www.solarwinds.com/public-sector/disa-stig-compliance). Published July 6, 2023\.

Security \- Configuring DHCP Snooping  \[Support\]. Cisco. [https://www.cisco.com/en/US/docs/general/Test/dwerblo/broken\_guide/snoodhcp.html\#wp1120427](https://www.cisco.com/en/US/docs/general/Test/dwerblo/broken_guide/snoodhcp.html#wp1120427). Published November 6, 2007\.

Ariganello, J.; “[More Is Less: The Challenge of Utilizing Multiple Security Tools](https://www.anomali.com/blog/more-is-less-the-challenge-of-utilizing-multiple-security-tools),” Anomali, 13 April 2022

Arora, S. (2023, November 7). *From Chaos to Confidence: The Indispensable Role of Security Architecture*. ISACA. [https://www.isaca.org/resources/news-and-trends/industry-news/2023/from-chaos-to-confidence-the-indispensable-role-of-security-architecture](https://www.isaca.org/resources/news-and-trends/industry-news/2023/from-chaos-to-confidence-the-indispensable-role-of-security-architecture#1)

Payment security explained: A guide for businesses | Stripe. (2023) [https://stripe.com/en-ca/resources/more/payment-security](https://stripe.com/en-ca/resources/more/payment-security)   
