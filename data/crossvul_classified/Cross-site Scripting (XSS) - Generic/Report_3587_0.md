# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3587_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3587_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 70-110 of the vulnerable file.


            if ($post->no_results) {
                header("HTTP/1.1 404 Not Found");
                $trigger->call("not_found");
                exit;
            }

            $main->display("feathers/".$post->feather, array("post" => $post, "ajax_reason" => $reason));
            break;

        case "preview":
            if (empty($_POST['content']))
                break;

            $trigger->filter($_POST['content'],
                             array("preview_".$_POST['feather'], "preview"),
                             $_POST['field'],
                             $_POST['feather']);

            echo "<h2 class=\"preview-header\">".__("Preview")."</h2>\n".
                 "<div class=\"preview-content\">".$_POST['content']."</div>";
            break;

        case "check_confirm":
            if (!$visitor->group->can("toggle_extensions"))
                show_403(__("Access Denied"), __("You do not have sufficient privileges to enable/disable extensions."));

            $dir = ($_POST['type'] == "module") ? MODULES_DIR : FEATHERS_DIR ;
            $info = YAML::load($dir."/".$_POST['check']."/info.yaml");
            fallback($info["confirm"], "");

            if (!empty($info["confirm"]))
                echo __($info["confirm"], $_POST['check']);

            break;

        case "organize_pages":
            foreach ($_POST['parent'] as $id => $parent)
                $sql->update("pages", array("id" => $id), array("parent_id" => $parent));

            foreach ($_POST['page_list'] as $index => $page)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -87,7 +87,7 @@
                              $_POST['feather']);
 
             echo "<h2 class=\"preview-header\">".__("Preview")."</h2>\n".
-                 "<div class=\"preview-content\">".$_POST['content']."</div>";
+                 "<div class=\"preview-content\">".fix($_POST['content'])."</div>";
             break;
 
         case "check_confirm":
```
