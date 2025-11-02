# 🧠 Comprehensive Web Security Assessment  
**From Reconnaissance to Privilege Escalation — A Hands-On Cybersecurity Simulation**

---

## 📌 Overview

Every breach begins with reconnaissance — and this project transforms that theory into practice.  
In just a few days, I simulated a **complete penetration testing engagement**, following an attacker’s journey from **information gathering** to **privilege escalation**.  

The assessment replicates a real-world **web application penetration test**, conducted in a controlled lab environment to identify, exploit, and document security weaknesses using industry standards such as **OWASP**, **MITRE ATT&CK**, and **CWE**.

---

## 🎯 Objective

To simulate a **professional web security assessment**, uncover vulnerabilities, exploit them responsibly, and provide actionable remediation strategies — all while documenting each phase like a real SOC or penetration testing report.

---

## 🧰 Tools and Technologies

| Category | Tools Used |
|-----------|-------------|
| **Reconnaissance** | nslookup, dig, Nmap |
| **Web Application Testing** | Burp Suite, OWASP ZAP |
| **Fuzzing & Enumeration** | Dirb, FFUF |
| **Analysis & Logging** | Wazuh, Splunk, YARA |
| **Reporting & Documentation** | Markdown, GitHub, VS Code |

---

## 🧩 Assessment Workflow

### 1️⃣ Reconnaissance  
Mapped target infrastructure using `nslookup` and `dig` to identify DNS records, IP addresses, and hosting metadata.  
Followed up with `Nmap` to discover open ports, services, and operating system details.

### 2️⃣ Vulnerability Identification  
Used **Burp Suite** and **OWASP ZAP** to intercept requests, manipulate parameters, and identify client-side and server-side weaknesses.

### 3️⃣ Exploitation  
Validated vulnerabilities including:
- **Privilege Escalation via Role Manipulation**  
- **Cross-Site Request Forgery (CSRF)**  
- **Insecure Direct Object Reference (IDOR)**  
- **Directory Listing Exposure**  
- **Insecure Session Management**  
- **Weak Password Policy**  
- **Server-Side Template Injection (SSTI)**  

### 4️⃣ Post-Exploitation  
Demonstrated account takeover, privilege abuse, and unauthorized data exposure.  
Captured and analyzed logs using **Wazuh** and **YARA** to simulate real SOC detection.

### 5️⃣ Reporting & Documentation  
Compiled all findings into a **structured technical report** — including impact, proof of concept, and mitigation strategies.

---

## ⚠️ Key Vulnerabilities Identified

| # | Vulnerability | Severity | Description |
|---|----------------|-----------|--------------|
| 1 | Privilege Escalation via Role Manipulation | 🔴 Critical | Bypassed access control by modifying role parameters |
| 2 | Cross-Site Request Forgery (CSRF) | 🟠 High | Unauthorized profile changes via forged POST request |
| 3 | Insecure Direct Object Reference (IDOR) | 🟠 High | Accessed and modified other users’ baskets |
| 4 | Directory Listing Exposure | 🟡 Medium | Public access to confidential files and logs |
| 5 | Insecure Session Management | 🟠 High | Tokens remained valid post-logout; vulnerable to replay |
| 6 | Weak Password Policy | 🟡 Medium | Accepted weak passwords without complexity checks |
| 7 | Server-Side Template Injection (SSTI) | 🔴 Critical | Remote code execution as root via template injection |

---

## 🧠 Sample Proof of Concept (PoC)

### Privilege Escalation via Role Manipulation

**Steps:**
1. Log in as a normal user.  
2. Intercept login response using **Burp Suite**.  
3. Modify the `role=user` parameter to `role=admin`.  
4. Forward the request — the app grants admin privileges.  

> **Impact:**  
> Full administrative access, user management, and configuration control.  

> **Fix:**  
> Enforce server-side RBAC validation and audit privilege changes.

---

## 🛡️ Recommendations Summary

- Implement **server-side validation** for all sensitive operations.  
- Enforce **Role-Based Access Control (RBAC)** and **CSRF tokens**.  
- Disable **directory listing** and restrict sensitive file access.  
- Use **secure cookie storage** for tokens (HttpOnly + SameSite).  
- Enforce **strong password policies** and integrate **MFA**.  
- Regularly scan for misconfigurations and apply security patches.

---

## 📄 Reporting Structure

| File | Description |
|------|-------------|
| [docs/methodology.md](./docs/methodology.md) | Assessment process following OWASP & PTES |
| [docs/vulnerabilities.md](./docs/vulnerabilities.md) | Detailed vulnerability write-ups |
| [docs/recommendations.md](./docs/recommendations.md) | Remediation and mitigation strategies |
| [docs/report_summary.md](./docs/report_summary.md) | Executive summary and conclusion |
| [report/Comprehensive_Web_Security_Assessment.pdf](./report/Comprehensive_Web_Security_Assessment.pdf) | Full formatted report for download |

---

## 🧩 Lessons Learned

- Every misconfiguration is an opportunity to improve detection.  
- Real-world attack simulation builds muscle memory for SOC response.  
- Strong documentation bridges the gap between discovery and remediation.  
- Combining **offensive** testing (YARA, Burp, FFUF) with **defensive** tools (Wazuh, Splunk) gives complete visibility.

---

## 🧾 Conclusion

This assessment revealed critical misconfigurations and insecure design patterns that could compromise confidentiality, integrity, and availability.  
By prioritizing immediate fixes and adopting secure coding practices, organizations can significantly strengthen their defense posture.

This project demonstrates my capability to perform:
- 🔍 Vulnerability discovery  
- ⚙️ Exploitation and post-exploitation  
- 🛡️ Detection and alert correlation  
- 🧾 Professional cybersecurity reporting  

---

## 📸 Screenshots (Sample)

> **Figure:** Burp Suite interception showing modified role parameter  
![Privilege Escalation Proof](./report/screenshots/privilege_escalation.png)

> **Figure:** YARA-triggered alert visible in Wazuh Dashboard  
![YARA Alert](./report/screenshots/yara_alert.png)

---

## 👨‍💻 Author

**👤 Babatunde Qodri**  
🎯 Cybersecurity Enthusiast | SOC Analyst in Training  
🔗 [LinkedIn](https://www.linkedin.com/in/your-linkedin-profile)  
💻 [GitHub](https://github.com/Talk2Babatunde)  
✉️ talk2babatunde@example.com  

---

## 🪪 License

This project is licensed under the [MIT License](./LICENSE).

---

> *A complete cybersecurity simulation — from scanning ports to privilege escalation — demonstrating real-world skills in threat detection, exploitation, and SOC reporting.*
