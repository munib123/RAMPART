# CrossVul Fix Pair: Uncontrolled Resource Consumption in yaml
**Pair ID:** 4546_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** yaml
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4546_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```yaml
Lines 1555-1595 of the vulnerable file.

  - regex: '(?:DoCoMo|\bMOT\b|\bLG\b|Nokia|Samsung|SonyEricsson).*(?:(?:Bot|Yeti)-Mobile|bots?/\d|(?:bot|crawler)\.html|(?:jump|google|Wukong)bot|ichiro/mobile|/spider|YahooSeeker)'
    regex_flag: 'i'
    device_replacement: 'Spider'
    brand_replacement: 'Spider'
    model_replacement: 'Feature Phone'

  # PTST / WebPageTest.org crawlers
  - regex: ' PTST/\d+(?:\.)?\d+$'
    device_replacement: 'Spider'
    brand_replacement: 'Spider'

  # Datanyze.com spider
  - regex: 'X11; Datanyze; Linux'
    device_replacement: 'Spider'
    brand_replacement: 'Spider'

  #########
  # WebBrowser for SmartWatch
  # @ref: https://play.google.com/store/apps/details?id=se.vaggan.webbrowser&hl=en
  #########
  - regex: '\bSmartWatch *\( *([^;]+) *; *([^;]+) *;'
    device_replacement: '$1 $2'
    brand_replacement: '$1'
    model_replacement: '$2'

  ######################################################################
  # Android parsers
  #
  # @ref: https://support.google.com/googleplay/answer/1727131?hl=en
  ######################################################################

  # Android Application
  - regex: 'Android Application[^\-]+ - (Sony) ?(Ericsson|) (.+) \w+ - '
    device_replacement: '$1 $2'
    brand_replacement: '$1$2'
    model_replacement: '$3'
  - regex: 'Android Application[^\-]+ - (?:HTC|HUAWEI|LGE|LENOVO|MEDION|TCT) (HTC|HUAWEI|LG|LENOVO|MEDION|ALCATEL)[ _\-](.+) \w+ - '
    regex_flag: 'i'
    device_replacement: '$1 $2'
    brand_replacement: '$1'
    model_replacement: '$2'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1572,7 +1572,7 @@
   # WebBrowser for SmartWatch
   # @ref: https://play.google.com/store/apps/details?id=se.vaggan.webbrowser&hl=en
   #########
-  - regex: '\bSmartWatch *\( *([^;]+) *; *([^;]+) *;'
+  - regex: '\bSmartWatch {0,2}\( {0,2}([^;]+) {0,2}; {0,2}([^;]+) {0,2};'
     device_replacement: '$1 $2'
     brand_replacement: '$1'
     model_replacement: '$2'
@@ -2584,7 +2584,7 @@
     device_replacement: '$1$2'
     brand_replacement: 'Huawei'
     model_replacement: '$2'
-  - regex: '; *([^;/]+) Build[/ ]Huawei(MT1-U06|[A-Z]+\d+[^\);]+)[^\);]*\)'
+  - regex: '; *([^;/]+) Build[/ ]Huawei(MT1-U06|[A-Z]+\d+[^\);]+)\)'
     device_replacement: '$1'
     brand_replacement: 'Huawei'
     model_replacement: '$2'
@@ -5126,7 +5126,7 @@
   # HbbTV (European and Australian standard)
   # written before the LG regexes, as LG is making HbbTV too
   ##########
-  - regex: '(HbbTV)/[0-9]+\.[0-9]+\.[0-9]+ \([^;]*; *(LG)E *; *([^;]*) *;[^;]*;[^;]*;\)'
+  - regex: '(HbbTV)/[0-9]+\.[0-9]+\.[0-9]+ \( {0,1};(LG)E {0,1};([^;]{0,30})'
     device_replacement: '$1'
     brand_replacement: '$2'
     model_replacement: '$3'
@@ -5141,7 +5141,7 @@
   - regex: '(HbbTV)/1\.1\.1 \(;;;;;\) Maple_2011'
     device_replacement: '$1'
     brand_replacement: 'Samsung'
-  - regex: '(HbbTV)/[0-9]+\.[0-9]+\.[0-9]+ \([^;]*; *(?:CUS:([^;]*)|([^;]+)) *; *([^;]*) *;.*;'
+  - regex: '(HbbTV)/[0-9]+\.[0-9]+\.[0-9]+ \([^;]{0,30}; {0,1}(?:CUS:([^;]*)|([^;]+)) {0,1}; {0,1}([^;]{0,30})'
     device_replacement: '$1'
     brand_replacement: '$2$3'
     model_replacement: '$4'
```
