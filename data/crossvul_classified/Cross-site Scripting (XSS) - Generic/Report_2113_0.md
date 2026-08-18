# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 2113_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2113_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 44-74 of the vulnerable file.

  $tmp = tempnam(sys_get_temp_dir(), "fnt");
  $font->open($tmp, Binary_Stream::modeWrite);
  $font->encode(array("OS/2"));
  $font->close();
  
  ob_end_clean();
  
  readfile($tmp);
  unlink($tmp);
  
  return;
} ?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Subset maker</title>
  <link rel="stylesheet" href="css/style.css" />
</head>
<body>
  <h1><?php echo $name; ?></h1>
  <form name="make-subset" method="post" action="?fontfile=<?php echo $fontfile; ?>">
    <label>
      Insert the text from which you want the glyphs in the subsetted font: <br />
      <textarea name="subset" cols="50" rows="20"></textarea>
    </label>
    <br />
    <button type="submit">Make subset!</button>
  </form>
</body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -61,7 +61,7 @@
   <link rel="stylesheet" href="css/style.css" />
 </head>
 <body>
-  <h1><?php echo $name; ?></h1>
+  <h1><?php echo htmlentities($name); ?></h1>
   <form name="make-subset" method="post" action="?fontfile=<?php echo $fontfile; ?>">
     <label>
       Insert the text from which you want the glyphs in the subsetted font: <br />
```
