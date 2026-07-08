# Vulnerability: Tongda OA Meeting - Unauthorized Access
**Classification:** TONGDA
**Source:** Nuclei Template (`tongda-meeting-unauth.yaml`)

## Description
Tongda Meeting Unauthorized Access were Detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/general/calendar/arrange/get_cal_list.php?starttime=1548058874&endtime=33165447106&view=agendaDay
```

