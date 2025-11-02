# ⚙️ Tools and Technologies Used  

This section outlines the core tools and frameworks used throughout the **Comprehensive Web Security Assessment**.  
Each tool was selected based on its ability to support **offensive testing**, **defensive monitoring**, and **incident response simulation** — ensuring an end-to-end evaluation of the web application’s security posture.

---

## 🧭 1️⃣ Reconnaissance and Scanning  

| Tool | Purpose | Key Use |
|------|----------|----------|
| **Nmap** | Network and port scanning | Identified open ports, services, and OS fingerprints. |
| **Whois / nslookup / dig** | DNS and domain reconnaissance | Gathered domain registration info, MX, and A records. |
| **Dirb / FFUF** | Directory brute-forcing | Enumerated hidden directories and sensitive files. |

**Highlight:**  
> Used Nmap’s `-A` flag to detect service versions and configurations, forming the foundation for vulnerability discovery.

---

## 🧪 2️⃣ Vulnerability Analysis and Exploitation  

| Tool | Purpose | Key Use |
|------|----------|----------|
| **Burp Suite** | Web interception and exploitation | Modified HTTP parameters, tested CSRF, IDOR, and privilege escalation. |
| **OWASP ZAP** | Automated web scanning | Detected XSS, CSRF, and missing security headers. |
| **Nikto** | Web server misconfiguration detection | Flagged outdated versions and directory listings. |
| **Metasploit Framework** | Controlled exploitation testing | Verified exploitability of misconfigurations. |

**Highlight:**  
> Burp Suite was used for manual exploitation and PoC validation, demonstrating hands-on proficiency in ethical hacking techniques.

---

## 🧩 3️⃣ Monitoring and Detection  

| Tool | Purpose | Key Use |
|------|----------|----------|
| **Wazuh SIEM** | Log analysis and alert correlation | Monitored endpoint activity and generated custom alerts (Rule ID: 110050). |
| **YARA** | Malware detection engine | Scanned PowerShell scripts and detected suspicious signatures. |
| **Sysmon** | System-level event monitoring | Collected process creation and network connection logs. |
| **Splunk** | Log visualization and analytics | Correlated network alerts for deeper investigation. |

**Highlight:**  
> A custom YARA rule triggered an automated Wazuh alert for a simulated PowerShell-based malware — showcasing practical SOC alert creation and rule tuning.

---

## 🧰 4️⃣ Reporting and Documentation  

| Tool | Purpose | Key Use |
|------|----------|----------|
| **Visual Studio Code** | Report writing and Markdown editing | Created professional documentation and formatted findings. |
| **GitHub** | Version control and project presentation | Hosted the entire project as a public SOC portfolio repository. |
| **Markdown / PDF Export** | Structured documentation | Generated clean, readable, and recruiter-friendly reports. |

**Highlight:**  
> All documentation was written in Markdown for clear GitHub rendering, linking technical depth to professional presentation.

---

## 🔐 5️⃣ Operating Environments  

| System | Role | Key Configuration |
|---------|------|-------------------|
| **Ubuntu Server (20.04)** | Wazuh Manager & SIEM Host | Hosted centralized monitoring and log correlation. |
| **Windows 10 VM** | Victim Machine | Installed Wazuh Agent, Sysmon, and YARA for endpoint testing. |
| **Kali Linux** | Attacker Machine | Ran Burp Suite, Dirb, and Metasploit for controlled exploitation. |
| **pfSense Firewall** | Network perimeter | Managed and inspected inbound/outbound traffic for test control. |

---

## 🧠 Key Takeaways  

- Combining **offensive tools (Burp, Nmap, FFUF)** and **defensive platforms (Wazuh, YARA)** gave 360° visibility into system behavior.  
- Real-time alerting through **custom YARA rules** demonstrated practical SOC integration.  
- Using **GitHub as a reporting environment** improved transparency, traceability, and technical presentation.  

---

## 📘 References  

- [Nmap Network Mapper](https://nmap.org/)  
- [OWASP ZAP Project](https://owasp.org/www-project-zap/)  
- [Wazuh Documentation](https://documentation.wazuh.com/current/)  
- [YARA Rules Reference](https://virustotal.github.io/yara/)  
