# CrossVul Fix Pair: Improper Neutralization of Alternate XSS Syntax in html
**Pair ID:** 4581_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-87
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4581_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Alternate XSS Syntax - The product does not neutralize or incorrectly neutralizes user-controlled input for alternate script syntax.

## Vulnerable Code
```html
Lines 5-44 of the vulnerable file.

                <li data-column-id="<?= $index ?>">
                    <div class="import-column-name">
                        <span>
                            <i class="column-success-icon text-success icon-check"></i>
                            <a
                                href="javascript:;"
                                class="column-ignore-button"
                                data-toggle="tooltip"
                                data-delay="300"
                                data-placement="right"
                                title="<?= e(trans('backend::lang.import_export.ignore_this_column')) ?>"
                                onclick="$.oc.importBehavior.ignoreFileColumn(this)"
                            >
                                <i class="icon-close"></i>
                            </a>
                            <a
                                href="javascript:;"
                                class="column-label"
                                onclick="$.oc.importBehavior.loadFileColumnSample(this)"
                            >
                                <?= $column ?>
                            </a>
                        </span>
                    </div>
                    <div class="import-column-bindings">
                        <ul data-empty-text="<?= e(trans('backend::lang.import_export.drop_column_here')) ?>"></ul>
                    </div>
                </li>
            <?php endforeach ?>
        </ul>
    <?php else: ?>
        <p class="upload-prompt">
            <?= e(trans('backend::lang.import_export.upload_valid_csv')) ?>
        </p>
    <?php endif ?>
</div>

<script>
    $.oc.importBehavior.bindColumnSorting()
</script>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -22,7 +22,7 @@
                                 class="column-label"
                                 onclick="$.oc.importBehavior.loadFileColumnSample(this)"
                             >
-                                <?= $column ?>
+                                <?= e($column) ?>
                             </a>
                         </span>
                     </div>
```
