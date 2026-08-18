# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1759_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1759_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 14-54 of the vulnerable file.

  preg_match("/^(NOMENU:1)$/m", $pageheader, $matches4);                        // for pages only: if NOMENU:1, no link in top-menu
  preg_match("/^URL:(.*)$/m", $pageheader, $matches5);                          // for articles: article's link    // for pages: top-menu's link 
  return array($pagecontent, $matches1[1], trim($matches2[1]), $matches3[1], $matches4[1], trim($matches5[1]));
}

$siteroot = substr($_SERVER['PHP_SELF'], 0,  - strlen(basename($_SERVER['PHP_SELF']))); // must have trailing slash, we don't use dirname because it can produce antislash on Windows
$requestedpage = basename(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
if (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === $siteroot) { $requestedpage = ""; }     // check if homepage 
$type =  strpos($_SERVER['REQUEST_URI'], 'article/') ? 'article' : 'page';
$pages = glob("./" . $type ."/*$requestedpage.{txt,md}", GLOB_BRACE);
if ($pages) { $page = $pages[0]; } else { $page = "./page/HIDDEN-404.txt"; $type = 'page'; }                 // default 404 error page
list($pagecontent, $pagetitle, $pageauthor, $pagedate, $pagenomenu, $pageurl) = getpage($page);
if (!$pageurl) { $pageurl = pathinfo($page)['filename']; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?php echo (trim($pagetitle) ? "$sitename - $pagetitle" : "$sitename")?></title>
  <base href="<?php echo $siteroot; ?>">
  <link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
<div class="header">
  <div class="logo"><a href="."><?php echo $sitename;?></a></div>
  <ul class="menu">
    <?php
    $pages = glob("./page/*.{txt,md}", GLOB_BRACE);
    foreach($pages as $page)
    {
      list($menupagecontent, $menupagetitle, $menupageauthor, $menupagedate, $menupagenomenu, $menupageurl) = getpage($page);
      if (!$menupagenomenu) { echo "<li><a href=\"" . ($menupageurl ? $menupageurl : strtolower($menupagetitle)) . "\">$menupagetitle</a></li>"; }
    }
    ?>
  </ul>
</div>
<div class="main">

<?php
require 'Parsedown.php';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,7 @@
   <meta charset="utf-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title><?php echo (trim($pagetitle) ? "$sitename - $pagetitle" : "$sitename")?></title>
-  <base href="<?php echo $siteroot; ?>">
+  <base href="<?php echo htmlspecialchars($siteroot, ENT_QUOTES); ?>">
   <link rel="stylesheet" type="text/css" href="style.css">
 </head>
 <body>
```
