# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 4292_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4292_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 24-58 of the vulnerable file.

                    <input type="text" name="title[]" value="<?= $trans_load != null && isset($trans_load[$language->abbr]['title']) ? $trans_load[$language->abbr]['title'] : '' ?>" class="form-control">
                </div>
                <?php
            } $i = 0;
            foreach ($languages as $language) {
                ?>
                <div class="form-group">
                    <label for="description<?= $i ?>">Description (<?= $language->name ?><img src="<?= base_url('attachments/lang_flags/' . $language->flag) ?>" alt="">)</label>
                    <textarea name="description[]" id="description<?= $i ?>" rows="50" class="form-control"><?= $trans_load != null && isset($trans_load[$language->abbr]['description']) ? $trans_load[$language->abbr]['description'] : '' ?></textarea>
                    <script>
                        CKEDITOR.replace('description<?= $i ?>');
                        CKEDITOR.config.entities = false;
                    </script>
                </div>
                <?php
                $i++;
            }
            ?>
            <div class="form-group">
                <?php if (isset($_POST['image'])) { ?>
                    <input type="hidden" name="old_image" value="<?= $_POST['image'] ?>">
                    <div><img class="img-responsive" src="<?= base_url('attachments/blog_images/' . $_POST['image']) ?>"></div>
                    <label for="userfile">Choose another image:</label>
                <?php } else { ?>
                    <label for="userfile">Upload image:</label>
                <?php } ?>
                <input type="file" id="userfile" name="userfile">
            </div>
            <button type="submit" name="submit" class="btn btn-default">Publish</button>
            <?php if ($id > 0) { ?>
                <a href="<?= base_url('admin/blog') ?>" class="btn btn-info">Cancel</a>
            <?php } ?>
        </form>
    </div>
</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -41,7 +41,7 @@
             ?>
             <div class="form-group">
                 <?php if (isset($_POST['image'])) { ?>
-                    <input type="hidden" name="old_image" value="<?= $_POST['image'] ?>">
+                    <input type="hidden" name="old_image" value="<?= htmlspecialchars($_POST['image']) ?>">
                     <div><img class="img-responsive" src="<?= base_url('attachments/blog_images/' . $_POST['image']) ?>"></div>
                     <label for="userfile">Choose another image:</label>
                 <?php } else { ?>
```
