# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 4542_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4542_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 23-52 of the vulnerable file.

TOKEN = TCHAR + "{1,}"

# RFC 5234 Appendix B.1 "Core Rules":
# VCHAR         =  %x21-7E
#                  ; visible (printing) characters
VCHAR = r"\x21-\x7e"

# header-field   = field-name ":" OWS field-value OWS
# field-name     = token
# field-value    = *( field-content / obs-fold )
# field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
# field-vchar    = VCHAR / obs-text

# Errata from: https://www.rfc-editor.org/errata_search.php?rfc=7230&eid=4189
# changes field-content to:
#
# field-content  = field-vchar [ 1*( SP / HTAB / field-vchar )
#                  field-vchar ]

FIELD_VCHAR = "[" + VCHAR + OBS_TEXT + "]"
FIELD_CONTENT = FIELD_VCHAR + "([ \t" + VCHAR + OBS_TEXT + "]+" + FIELD_VCHAR + "){,1}"
FIELD_VALUE = "(" + FIELD_CONTENT + "){0,}"

HEADER_FIELD = re.compile(
    tobytes(
        "^(?P<name>" + TOKEN + "):" + OWS + "(?P<value>" + FIELD_VALUE + ")" + OWS + "$"
    )
)

OWS_STRIP = re.compile(OWS + "(?P<value>.*?)" + OWS)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,13 +40,13 @@
 #                  field-vchar ]
 
 FIELD_VCHAR = "[" + VCHAR + OBS_TEXT + "]"
-FIELD_CONTENT = FIELD_VCHAR + "([ \t" + VCHAR + OBS_TEXT + "]+" + FIELD_VCHAR + "){,1}"
-FIELD_VALUE = "(" + FIELD_CONTENT + "){0,}"
+# Field content is more greedy than the ABNF, in that it will match the whole value
+FIELD_CONTENT = FIELD_VCHAR + "+(?:[ \t]+" + FIELD_VCHAR + "+)*"
+# Which allows the field value here to just see if there is even a value in the first place
+FIELD_VALUE = "(?:" + FIELD_CONTENT + ")?"
 
 HEADER_FIELD = re.compile(
     tobytes(
         "^(?P<name>" + TOKEN + "):" + OWS + "(?P<value>" + FIELD_VALUE + ")" + OWS + "$"
     )
 )
-
-OWS_STRIP = re.compile(OWS + "(?P<value>.*?)" + OWS)
```
