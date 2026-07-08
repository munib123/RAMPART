# Vulnerability: KevinLAB Devices Detection
**Classification:** IOT
**Source:** Nuclei Template (`kevinlab-device-detect.yaml`)

## Description
KevinLab is a venture company specialized in IoT, Big Data, A.I based energy management platform. KevinLAB's BEMS (Building Energy Management System) enables efficient energy management in buildings by collecting and analyzing various information of energy usage and facilities as well as efficiency and indoor environment control.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pages/
GET {{BaseURL}}/dashboard/
```

