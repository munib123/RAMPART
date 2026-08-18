# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5857_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5857_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 925-965 of the vulnerable file.

        $absurl = htmlspecialchars($link['url']);
        if (startsWith($absurl,'?')) $absurl=$pageaddr.$absurl;  // make permalink URL absolute
        if ($usepermalinks===true)
            echo '<item><title>'.htmlspecialchars($link['title']).'</title><guid isPermaLink="false">'.$guid.'</guid><link>'.$guid.'</link>';
        else
            echo '<item><title>'.htmlspecialchars($link['title']).'</title><guid isPermaLink="false">'.$guid.'</guid><link>'.$absurl.'</link>';
        if (!$GLOBALS['config']['HIDE_TIMESTAMPS'] || isLoggedIn()) echo '<pubDate>'.htmlspecialchars($rfc822date)."</pubDate>\n";
        if ($link['tags']!='') // Adding tags to each RSS entry (as mentioned in RSS specification)
        {
            foreach(explode(' ',$link['tags']) as $tag) { echo '<category domain="'.htmlspecialchars($pageaddr).'">'.htmlspecialchars($tag).'</category>'."\n"; }
        }

        // Add permalink in description
        $descriptionlink = '(<a href="'.$guid.'">Permalink</a>)';
        // If user wants permalinks first, put the final link in description
        if ($usepermalinks===true) $descriptionlink = '(<a href="'.$absurl.'">Link</a>)';
        if (strlen($link['description'])>0) $descriptionlink = '<br>'.$descriptionlink;
        echo '<description><![CDATA['.nl2br(keepMultipleSpaces(text2clickable(htmlspecialchars($link['description'])))).$descriptionlink.']]></description>'."\n</item>\n";
        $i++;
    }
    echo '</channel></rss><!-- Cached version of '.pageUrl().' -->';

    $cache->cache(ob_get_contents());
    ob_end_flush();
    exit;
}

// ------------------------------------------------------------------------------------------
// Ouput the last N links in ATOM format.
function showATOM()
{
    header('Content-Type: application/atom+xml; charset=utf-8');

    // $usepermalink : If true, use permalink instead of final link.
    // User just has to add 'permalink' in URL parameters. eg. http://mysite.com/shaarli/?do=atom&permalinks
    $usepermalinks = isset($_GET['permalinks']);

    // Cache system
    $query = $_SERVER["QUERY_STRING"];
    $cache = new pageCache(pageUrl(),startsWith($query,'do=atom') && !isLoggedIn());
    $cached = $cache->cachedVersion(); if (!empty($cached)) { echo $cached; exit; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -942,7 +942,7 @@
         echo '<description><![CDATA['.nl2br(keepMultipleSpaces(text2clickable(htmlspecialchars($link['description'])))).$descriptionlink.']]></description>'."\n</item>\n";
         $i++;
     }
-    echo '</channel></rss><!-- Cached version of '.pageUrl().' -->';
+    echo '</channel></rss><!-- Cached version of '.htmlspecialchars(pageUrl()).' -->';
 
     $cache->cache(ob_get_contents());
     ob_end_flush();
@@ -1027,7 +1027,7 @@
     $feed.='<author><name>'.htmlspecialchars($pageaddr).'</name><uri>'.htmlspecialchars($pageaddr).'</uri></author>';
     $feed.='<id>'.htmlspecialchars($pageaddr).'</id>'."\n\n"; // Yes, I know I should use a real IRI (RFC3987), but the site URL will do.
     $feed.=$entries;
-    $feed.='</feed><!-- Cached version of '.pageUrl().' -->';
+    $feed.='</feed><!-- Cached version of '.htmlspecialchars(pageUrl()).' -->';
     echo $feed;
 
     $cache->cache(ob_get_contents());
@@ -1104,7 +1104,7 @@
         echo '<description><![CDATA['.$html.']]></description>'."\n</item>\n\n";
 
     }
-    echo '</channel></rss><!-- Cached version of '.pageUrl().' -->';
+    echo '</channel></rss><!-- Cached version of '.htmlspecialchars(pageUrl()).' -->';
 
     $cache->cache(ob_get_contents());
     ob_end_flush();
@@ -1747,11 +1747,11 @@
         }
         $LINKSDB->savedb();
 
-        echo '<script language="JavaScript">alert("File '.$filename.' ('.$filesize.' bytes) was successfully processed: '.$import_count.' links imported.");document.location=\'?\';</script>';
+        echo '<script language="JavaScript">alert("File '.json_encode($filename).' ('.$filesize.' bytes) was successfully processed: '.$import_count.' links imported.");document.location=\'?\';</script>';
     }
     else
     {
-        echo '<script language="JavaScript">alert("File '.$filename.' ('.$filesize.' bytes) has an unknown file format. Nothing was imported.");document.location=\'?\';</script>';
+        echo '<script language="JavaScript">alert("File '.json_encode($filename).' ('.$filesize.' bytes) has an unknown file format. Nothing was imported.");document.location=\'?\';</script>';
     }
 }
 
```
