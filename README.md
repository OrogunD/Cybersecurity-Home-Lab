# Cybersecurity-Home-Lab
Personal cybersecurity lab for vulnerability assessment and penetration testing practice
**Author:** Daniel Orogun  
**Contact:** orogund10@gmail.com | [LinkedIn](https://linkedin.com/in/daniel-orogun-800798177)  
**Started:** December 2025

## Lab Environment

### Infrastructure
- **Hypervisor:** Oracle VirtualBox 7.x
- **Network Configuration:** Bridged Adapter (isolated network segment)
- **Host System:** Windows

- ### Virtual Machines
1. **Metasploitable 2** (Vulnerable Target)
   - OS: Ubuntu Linux
   - IP: 192.168.1.217
   - Purpose: Intentionally vulnerable system for practising exploitation techniques

2. **Kali Linux 2025.2** (Attack Platform)
   - OS: Kali Linux
   - IP: 192.168.1.166
   - Purpose: Penetration testing distribution with pre-installed security tools


## Project 1: Network Reconnaissance & Vulnerability Discovery

### Objective
Identify open ports and vulnerable services on the target system using industry-standard reconnaissance tools.

### Tools Used
- **Nmap** - Network mapper and port scanner
- **ifconfig/ip** - Network configuration utilities

### Methodology

#### 1. Network Configuration
- Configured both VMs on a bridged network for inter-VM communication
- Verified connectivity using ICMP ping tests
- Confirmed 0% packet loss between attacker and target systems
  ![Ping Test Results](kali-ping-test.png)
#### 2. Port Scanning
Executed a comprehensive TCP port scan with service version detection:
```bash
nmap -sV 192.168.1.217
```
**Scan Parameters:**
- `-sV`: Service version detection
- Target: 192.168.1.217 (Metasploitable 2)

- ### Key Findings

#### Critical Vulnerabilities Discovered

**23 open ports identified** with multiple high-risk services:

| Port | Service | Version | Risk Level |
|------|---------|---------|------------|
| 21 | FTP | vsftpd 2.3.4 | **CRITICAL** |
| 22 | SSH | OpenSSH 4.7p1 | HIGH |
| 139/445 | SMB | Samba 3.X | HIGH |
| 1524 | Bindshell | Metasploitable root shell | **CRITICAL** |
| 3306 | MySQL | 5.0.51a | MEDIUM |
| 5432 | PostgreSQL | 8.3.0 - 8.3.7 | MEDIUM |
| 8180 | HTTP | Apache Tomcat | MEDIUM |

![Nmap Scan Results](nmap-scan-results.png)

#### Vulnerability Analysis

**vsftpd 2.3.4 (Port 21):**
- Known backdoor vulnerability (CVE-2011-2523)
- Allows unauthenticated remote code execution
- Exploitable via Metasploit Framework

**Bindshell (Port 1524):**
- Direct root shell access without authentication
- Represents catastrophic security failure
- Indicates complete system compromise

**Samba 3. X (Ports 139/445):**
- Multiple known vulnerabilities in the file-sharing protocol
- Potential for remote code execution
- Common target in enterprise environments

**Legacy Database Services:**
- MySQL 5.0.51a and PostgreSQL 8.3 both contain known CVEs
- Default configurations often have weak authentication
- Database compromise can lead to data exfiltration

### Security Implications

This scan demonstrates multiple critical security failures:

1. **Outdated Software:** All identified services are running legacy versions with publicly known vulnerabilities
2. **Excessive Attack Surface:** 23 open ports provide numerous entry points for attackers
3. **No Network Segmentation:** All services are exposed on a single network interface
4. **Lack of Patch Management:** Years-old vulnerabilities remain unpatched

### Defensive Recommendations

- To implement an aggressive patch management policy
- Close unnecessary ports and disable unused services
- Deploy network segmentation to isolate critical systems
- Implement intrusion detection/prevention systems (IDS/IPS)
- Regular vulnerability scanning and penetration testing
- Deploy host-based firewalls with default-deny policies

## Disclaimer

Please guys, this is a lab environment,  and I am using it for **educational and authorised security research purposes only**. All activities are conducted in an isolated virtual environment with no connection to production systems. Unauthorised access to computer systems is illegal.
