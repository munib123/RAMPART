# Vulnerability: Raspberry Shake Config Detection
**Classification:** MISCONFIG
**Source:** Nuclei Template (`raspberry-shake-config.yaml`)

## Description
The Shake Board digitizer receives, processes, and interprets the sensor data in real-time, allowing for the Raspberry Pi computer to export the data for easy access. The data output can be displayed and analyzed using our own comprehensive set of web tools or any standard seismological software.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

