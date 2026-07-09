# Nuclei Template: Apache Hadoop YARN ResourceManager - Remote Code Execution
**Template ID:** hadoop-unauth-rce
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** Critical
**CWE:** CWE-306
**Source:** Nuclei Template (`hadoop-unauth-rce.yaml`)

## Vulnerability Information & PoC

## Description
Apache Hadoop YARN ResourceManager is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/ws/v1/cluster/apps/new-application
```

## References
- http://archive.hack.lu/2016/Wavestone%20-%20Hack.lu%202016%20-%20Hadoop%20safari%20-%20Hunting%20for%20vulnerabilities%20-%20v1.0.pdf
- https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/hadoop_unauth_exec.rb
- https://github.com/vulhub/vulhub/tree/master/hadoop/unauthorized-yarn
- https://github.com/Al1ex/Hadoop-Yarn-ResourceManager-RCE
