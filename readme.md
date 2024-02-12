# Ivanti VPN Issues Links List


## First Two Vulnerabilities

- Named "ConnectAround" by Kevin Beaumont
- [CVE-2023-46805](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4680) - Authentication bypass
- [CVE-2024-21887](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21887)- Administrators can execute commands at operating system level
- [Ivanti knowledge base article on ConnectAround and the other three](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US)

- Exploit: [Metasploit module](http://packetstormsecurity.com/files/176668/Ivanti-Connect-Secure-Unauthenticated-Remote-Code-Execution.html) that uses the two of these to run commands on devices:

- [Blog post by Caitlin Condon at Rapid7](https://www.rapid7.com/blog/post/2024/01/11/etr-zero-day-exploitation-of-ivanti-connect-secure-and-policy-secure-gateways/)
- [CISA Alert 2024/01/10](https://www.cisa.gov/news-events/alerts/2024/01/10/ivanti-releases-security-update-connect-secure-and-policy-secure-gateways)

- Mitigation [Ivanti KnowledgeBase article](https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways)


## Second Two Vulnerabilities


[CVE-2024-21888](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21888) - Privilege escalation in web interface from user to administrator
[CVE-2024-21893](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21893) - SSRF allowing user-level access without authentication

[Ivanti Knowledge Base article on third and fourth vulns](https://forums.ivanti.com/s/article/CVE-2024-21888-Privilege-Escalation-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US)

[TechCrunch piece on third and fourth vulns](https://techcrunch.com/2024/01/31/ivanti-patches-two-zero-days-under-attack-but-finds-another/)
[CISA Supplemental Directive updated for third and fourth vulns](https://www.cisa.gov/news-events/directives/supplemental-direction-v1-ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure)
[Reporting on the CISA directive](https://therecord.media/federal-civilian-agencies-ordered-to-disconnect-at-risk-ivanti-products-cisa)

## Fifth Vulnerability

- disclosed Feb 8/9
- exploited by Feb 9

- [CVE-2024-22024](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-22024)
- [Ivanti Knowledge base article on fifth vulnerability](https://forums.ivanti.com/s/article/CVE-2024-22024-XXE-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure?language=en_US)
- [Open Source unvetted Scanner for CVE-2024-22024](https://github.com/0dteam/CVE-2024-22024/blob/main/cve_2024_22024.py)

- [Bleeping Computer article on CVE-2024-22024](https://www.bleepingcomputer.com/news/security/ivanti-patch-new-connect-secure-auth-bypass-bug-immediately/)
- [Register article on fifth vulnerability](https://www.theregister.com/2024/02/09/ivanti_discloses_fifth_ics_vulnerability/)

- [Watchtowr Labs article on discovering vuln](https://labs.watchtowr.com/are-we-now-part-of-ivanti/)



