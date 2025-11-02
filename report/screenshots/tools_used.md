# 🧰 Tools Used — Comprehensive Web Security Assessment

This project was designed to assess the security posture of a web application through detailed vulnerability analysis and detection using both manual and automated techniques.  
The following tools were utilized throughout the project to identify security flaws, simulate exploitation, and validate detection rules within a SOC environment.

---

## 1️⃣ Web Application and Vulnerability Testing Tools

| Tool | Purpose |
|------|----------|
| **Burp Suite** | Used as the main testing tool for intercepting and analyzing web traffic. It helped detect and exploit vulnerabilities such as *Insecure Direct Object Reference (IDOR)*, *Privilege Escalation via Parameter Tampering*, and *Cross-Site Request Forgery (CSRF)*. |
| **OWASP ZAP** | Served as an automated scanner to detect OWASP Top 10 vulnerabilities like missing security headers, weak authentication mechanisms, and misconfigured cookies. |
| **Nikto** | Performed server-side scanning to detect outdated software versions, default files, and potential misconfigurations. |
| **Kali Linux Toolkit** | Provided access to essential utilities like `Nmap`, `Dirb`, and enumeration scripts for supporting web reconnaissance. |

> These tools formed the offensive side of the assessment — identifying and exploiting weak points in the application for deeper analysis.

---

## 2️⃣ Security Monitoring and Detection Tools

| Tool | Purpose |
|------|----------|
| **Wazuh** | Deployed as the central SIEM platform for log monitoring, rule-based alerting, and security event correlation. |
| **YARA** | Used for malware detection and behavior analysis. Integrated with Wazuh to detect suspicious PowerShell scripts or potentially malicious activity. |
| **Sysmon** | Provided detailed Windows event logs (process creation, registry changes, network connections) for endpoint visibility. |
| **Filebeat** | Configured to forward logs from the endpoint system to the Wazuh Manager for centralized collection and correlation. |
| **Auditd** | Deployed on the Ubuntu system to monitor command executions and record audit events for analysis within Wazuh. |

> Integration between YARA and Wazuh was a major component of this assessment — confirming that custom detection rules could successfully trigger alerts for suspicious PowerShell activity.

---

## 3️⃣ System and Network Monitoring Tools

| Tool | Purpose |
|------|----------|
| **pfSense** | Acted as a virtual firewall, routing and controlling network traffic between the attacker and victim machines. |
| **Snort IDS** | Monitored live network traffic for intrusion patterns and relayed alerts to the monitoring console. |
| **Wireshark** | Captured and analyzed network packets to verify Snort detections and observe attack traffic during simulations. |

> These tools simulated a realistic defensive setup — providing visibility across the network layer during exploitation and detection tests.

---

## 4️⃣ Logging, Forensics, and Verification Tools

| Tool | Purpose |
|------|----------|
| **EvtxECmd** | Parsed Windows event logs into readable formats for reviewing system activities and potential intrusion traces. |
| **Wazuh Logtest Utility** | Validated the syntax and functionality of custom Wazuh rules before production use. |
| **Wazuh Alerts Log** | Continuously monitored with `sudo tail -f /var/ossec/logs/alerts/alerts.log | grep 110050` to confirm rule triggering and log forwarding. |

> These tools helped validate that detection events were successfully logged and correlated within the SOC workflow.

---

## 5️⃣ Reporting and Documentation Tools

| Tool | Purpose |
|------|----------|
| **Visual Studio Code** | Used to document findings, edit Markdown files, and manage version control through Git. |
| **Git & GitHub** | Managed versioning of assessment artifacts and hosted project documentation for recruiters and reviewers. |
| **ReportLab / Microsoft Word** | Used to compile the final professional assessment report (`Comprehensive_Web_Security_Assessment.pdf`). |

> Documentation was maintained consistently in Markdown format for readability, transparency, and proper evidence tracking.

---

## ✅ Summary

The tools above supported every phase of the assessment:
- **Burp Suite** and **OWASP ZAP** exposed vulnerabilities.  
- **Wazuh** and **YARA** correlated and detected suspicious behavior.  
- **Wireshark**, **Snort**, and **pfSense** provided network-level visibility.  
- **VS Code** and **GitHub** ensured structured reporting and professionalism.

> Together, they created a full offensive and defensive workflow, proving hands-on experience in both vulnerability exploitation and threat detection.

---

**Author:** *Babatunde Qodri*  
*Cybersecurity Analyst | SOC Trainee | Blue Team & Web Security Enthusiast*  
🔗 [LinkedIn](https://www.linkedin.com/in/babatundeqodri) • [GitHub](https://github.com/Talk2Babatunde)
