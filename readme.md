# Ivanti VPN Issues Links List

## Vulnerability Chart of Quick Links

| CVE Link | Type | Vendor KB |
| -------- | ---- | --------- |
|[CVE-2023-46805](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4680) | Authentication Bypass | [KB-2023-46805-and-2024-21887](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways) | 
|[CVE-2024-21887](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21887) | Command Execution for Authn'd Admins | [KB-2023-46805-and-2024-21887](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways) | 
|[CVE-2024-21888](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21888) | Privilege escalation in web interface from user to administrator | [KB-CVE-2024-21888-and-21893](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |
|[CVE-2024-21893](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21893) | SSRF allowing user-level access without authentication | [KB-CVE-2024-21888-and-21893](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |
|[CVE-2024-22024](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22024) | Authentication Bypass via XXE in SAML | [Ivanti Knowledge base article on fifth vulnerability](https://forums.ivanti.com/s/article/CVE-2024-22024-XXE-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |


## CVE-2023-46805 and CVE-2024-21887 -  Authentication Bypass and Command Execution

| Resource Type        | Link | Notes |
| -------------------- | ---- | ----- |
| CVE                  | [CVE-2023-46805](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4680) | Authentication Bypass |
| CVE                  | [CVE-2024-21887](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21887) | Command Execution for Authn'd Admins | 
| Vendor KB Article    | [KB-2023-46805-and-2024-21887](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways) | 
| Exploit              | [Metasploit module](http://packetstormsecurity.com/files/176668/Ivanti-Connect-Secure-Unauthenticated-Remote-Code-Execution.html) | Chains together CVE-2023-46805 and CVE-2024-21887 | 
| Blog Post            | [Blog post by Caitlin Condon at Rapid7](https://www.rapid7.com/blog/post/2024/01/11/etr-zero-day-exploitation-of-ivanti-connect-secure-and-policy-secure-gateways/) | |
| CISA Alert           | [CISA Alert 2024/01/10](https://www.cisa.gov/news-events/alerts/2024/01/10/ivanti-releases-security-update-connect-secure-and-policy-secure-gateways) ||| 


## CVE-2024-21888 and CVE-2024-21893

| Resource Type        | Link | Notes |
| -------------------- | ---- | ----- |
| CVE                  | [CVE-2024-21888](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21888) | Privilege escalation in web interface from user to administrator | [KB-CVE-2024-21888-and-21893](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |
| CVE                  | [CVE-2024-21893](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21893) | SSRF allowing user-level access without authentication | 
| Vendor KB Article    | [KB-CVE-2024-21888-and-21893](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) | |
| Press                | [TechCrunch piece on third and fourth vulns](https://techcrunch.com/2024/01/31/ivanti-patches-two-zero-days-under-attack-but-finds-another/) ||
| CISA Directive       | [CISA Supplemental Directive updated for third and fourth vulns](https://www.cisa.gov/news-events/directives/supplemental-direction-v1-ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure) ||
| Press                | [Reporting on the CISA directive](https://therecord.media/federal-civilian-agencies-ordered-to-disconnect-at-risk-ivanti-products-cisa) ||



## CVE-2024-22024 - disclosed Friday 2/9/24

| Resource Type | Link | Notes |
| ------------- | ---- | ----- |
| CVE           | [CVE-2024-22024](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22024) | Authentication Bypass via XXE in SAML | 
| Vendor KB    |  [Ivanti Knowledge base article on fifth vulnerability](https://forums.ivanti.com/s/article/CVE-2024-22024-XXE-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure) |
| Tool           | [Open Source unvetted Scanner for CVE-2024-22024](https://github.com/0dteam/CVE-2024-22024/blob/main/cve_2024_22024.py) || 
| Press          | [Bleeping Computer article on CVE-2024-22024](https://www.bleepingcomputer.com/news/security/ivanti-patch-new-connect-secure-auth-bypass-bug-immediately/) ||
| Press          | [Register article on fifth vulnerability(https://www.theregister.com/2024/02/09/ivanti_discloses_fifth_ics_vulnerability/)| |
| Discoverer     | [Watchtowr Labs article on discovering vuln](https://labs.watchtowr.com/are-we-now-part-of-ivanti/) ||



