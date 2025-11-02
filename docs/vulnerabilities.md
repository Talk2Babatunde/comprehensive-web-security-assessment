# 🚨 Vulnerabilities and Exploitation Findings  

This section presents the detailed findings from the **Comprehensive Web Security Assessment**, covering each vulnerability discovered, how it was exploited, its potential business impact, and actionable recommendations.  
All findings align with **OWASP Top 10 (2021)** and **CWE** classifications to reflect real-world exploitability.

---

## 1️⃣ Privilege Escalation via Role Manipulation  

**Severity:** 🔴 Critical  
**OWASP Category:** A05:2021 – Security Misconfiguration  
**CWE ID:** CWE-269 – Improper Privilege Management  

### 🔍 Description  
The web application failed to enforce server-side role validation. By modifying the `user_role` parameter in a POST request, a standard user could elevate privileges to an administrator level.  

### 🧠 Proof of Concept (PoC)
Using **Burp Suite**, the request was intercepted and altered:

```http
POST /update_user HTTP/1.1
Host: vulnerableapp.local
Content-Type: application/x-www-form-urlencoded

user_role=admin
💣 Impact

Full access to restricted admin panels.

Unauthorized control over users and configurations.

Potential for complete system takeover.

🧩 Recommendation

Enforce strict server-side validation for user roles.

Implement Role-Based Access Control (RBAC).

Log and alert all privilege modification events.

2️⃣ Cross-Site Request Forgery (CSRF)

Severity: 🟠 High
OWASP Category: A01:2021 – Broken Access Control
CWE ID: CWE-352 – Cross-Site Request Forgery

🔍 Description

Critical application actions lacked CSRF protection. Attackers could trick authenticated users into performing unintended actions such as changing passwords or email addresses.

🧠 Proof of Concept (PoC)

A crafted malicious HTML form automatically submitted a password change request:

<form action="https://vulnerableapp.local/update_password" method="POST">
  <input type="hidden" name="password" value="P@wned123">
  <input type="submit" value="Click me!">
</form>


When hosted on a remote domain, this form executed on behalf of an authenticated user without their consent.

💣 Impact

Account hijacking and data alteration.

Loss of user trust and application integrity.

🧩 Recommendation

Add anti-CSRF tokens for all POST requests.

Validate the Origin or Referer header.

Implement SameSite cookie attributes.

3️⃣ Insecure Direct Object Reference (IDOR)

Severity: 🟠 High
OWASP Category: A01:2021 – Broken Access Control
CWE ID: CWE-639 – Authorization Bypass Through User-Controlled Key

🔍 Description

The application exposed user identifiers directly in URLs, allowing attackers to manipulate parameters and access other users’ data.

🧠 Proof of Concept (PoC)

By changing the user ID in the request:

GET /view_invoice?id=102


An attacker accessed another user’s billing record.

💣 Impact

Unauthorized access to sensitive financial information.

GDPR and privacy compliance risks.

🧩 Recommendation

Implement server-side ownership checks.

Use indirect references (UUIDs) instead of numeric IDs.

4️⃣ Directory Listing Exposure

Severity: 🟡 Medium
OWASP Category: A05:2021 – Security Misconfiguration
CWE ID: CWE-548 – Information Exposure Through Directory Listing

🔍 Description

The server displayed directory contents when index files were missing. Sensitive .bak, .log, and .config files were publicly accessible.

🧠 Proof of Concept (PoC)

Visiting /uploads/ revealed:

index.html
backup_2023.bak
config.php~

💣 Impact

Exposure of database credentials or backup files.

Potential to aid further exploitation.

🧩 Recommendation

Disable directory browsing (Options -Indexes for Apache, autoindex off; for Nginx).

Restrict file access and monitor directory exposure.

5️⃣ Weak Password Policy

Severity: 🟡 Medium
OWASP Category: A07:2021 – Identification and Authentication Failures
CWE ID: CWE-521 – Weak Password Requirements

🔍 Description

The application accepted simple passwords such as 12345 and password.
No complexity, length, or character validation was enforced.

💣 Impact

Increased susceptibility to brute-force attacks.

Compromise of multiple accounts via credential stuffing.

🧩 Recommendation

Enforce minimum 12-character passwords with mixed character sets.

Use bcrypt or Argon2 for password hashing.

Integrate account lockout after 5 failed attempts.

6️⃣ Missing Security Headers

Severity: 🟢 Low
OWASP Category: A05:2021 – Security Misconfiguration
CWE ID: CWE-16 – Configuration Issues

🔍 Description

Critical HTTP headers such as X-Frame-Options, Content-Security-Policy, and Strict-Transport-Security were missing.

💣 Impact

Exposure to clickjacking and man-in-the-middle (MITM) attacks.

🧩 Recommendation

Add the following headers in the server configuration:

Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self';

🧾 Summary Table
#	Vulnerability	Severity	Category	CWE ID
1	Privilege Escalation	🔴 Critical	A05:2021	CWE-269
2	CSRF	🟠 High	A01:2021	CWE-352
3	IDOR	🟠 High	A01:2021	CWE-639
4	Directory Listing	🟡 Medium	A05:2021	CWE-548
5	Weak Password Policy	🟡 Medium	A07:2021	CWE-521
6	Missing Security Headers	🟢 Low	A05:2021	CWE-16
🧠 Insights and Lessons

Misconfigurations can grant unintended administrative access.

OWASP Top 10 vulnerabilities still dominate most web applications.

Detection and alerting through Wazuh + YARA dramatically improve visibility.

Continuous patching and testing are key to maintaining resilience.

📘 References

OWASP Testing Guide v4

MITRE ATT&CK Framework

CWE Vulnerability Database