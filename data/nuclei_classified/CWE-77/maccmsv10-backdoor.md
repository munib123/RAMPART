# Vulnerability: Maccmsv10 - Backdoor Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`maccmsv10-backdoor.yaml`)

## Description
Maccmsv10 contains a backdoor which can be exploited by remote attackers. The backdoor is accessible via the '/index.php/bbs/index/download' endpoint and the special 'getpwd' parameter value of 'WorldFilledWithLove'. Exploitation of this vulnerability will allow remote attackers to execute code.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/index.php/bbs/index/download?url=/etc/passwd&name=1.txt&local=1
```

