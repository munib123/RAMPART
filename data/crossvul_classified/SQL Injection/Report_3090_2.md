# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3090_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3090_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 205-245 of the vulnerable file.

                                </script>
                                ';
                            System::adminAsset($asset);

                            unset($lang);
                        }

                        echo '</div>';
                    } else {
                        ?>
                        <div class="form-group">
                        <label for="title"><?=TITLE; ?></label>
                        <input type="title" name="title" class="form-control" id="title" placeholder="Post Title" value="<?=$title; ?>">
                        </div>
                        <div class="form-group">
                        <label for="content"><?=CONTENT; ?></label> <a href="#" id="toggleEditor" class="btn btn-danger btn-xs pull-right"><i class="fa fa-desktop"></i> Editor</a>
                        <textarea name="content" class="form-control content editor" id="content" rows="20"><?=$content; ?></textarea>
                        <div id="myGrid"><?=$content; ?></div>
                        </div>
                        <?php
                    }
                ?>
                </div>
                <div class="col-sm-4">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title"><?=OPTIONS;?></h3>
                        </div>
                        <div class="panel-body">

                            <div class="form-group">
                                <label><?=STATUS;?></label>
                                <select name="status" class="form-control">
                                    <option value="1" <?=$pub;
?>><?=PUBLISH;?></option>
                                    <option value="0" <?=$unpub;
?>><?=UNPUBLISH;?></option>
                                </select>
                                <small><?=PUBLISHED;
?> or <?=UNPUBLISHED;?></small>
                            </div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -222,7 +222,9 @@
                         <div id="myGrid"><?=$content; ?></div>
                         </div>
                         <?php
+
                     }
+                    Hooks::run('page_param_form', $data);
                 ?>
                 </div>
                 <div class="col-sm-4">
```
