# HackerOne Report: Full Path Disclosure (2)
**Report ID:** 8013
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
During the import of an XML file,I edited the "file" to "url" for importing XML's through URL.So it became:
```html
<input id="importFileXML" class="form-control" type="url" name="importFileXML"></input>
```
And then I tried to import a random XML file.I tried with this:
http://www.swarthmore.edu/libraries.xml
It was not a valid XML file.And after the importing it showed the following error which discloses full path of the application.

```text
Notice: Undefined index: importFileXML in /var/www/vhosts/lvps178-77-99-228.dedicated.hosteurope.de/httpdocs_localize/index.php on line 421 
```

## Discussion & Remediation Timeline
