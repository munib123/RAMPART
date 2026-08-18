# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 3090_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3090_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 179-219 of the vulnerable file.

                            });
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
                        <label for="content"><?=CONTENT; ?></label>
                        <textarea name="content" class="form-control hidden content editor" id="content" rows="" ><?=$content; ?></textarea>
                    </div>
                <?php
                }
                ?>
                </div>
                <div class="col-md-4">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title"><?=OPTIONS;?></h3>
                        </div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label><?=CATEGORY;?></label>
                                <?php
                                    $vars = array(
                                                'order_by' => 'name',
                                                'name' => 'cat',
                                                'sort' => 'ASC',
                                                'type' => 'post',
                                            );
                                    if (isset($cat)) {
                                        $vars = array_merge($vars, array('selected' => $cat));
                                    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -196,7 +196,9 @@
                         <textarea name="content" class="form-control hidden content editor" id="content" rows="" ><?=$content; ?></textarea>
                     </div>
                 <?php
+
                 }
+                Hooks::run('post_param_form', $data);
                 ?>
                 </div>
                 <div class="col-md-4">
```
