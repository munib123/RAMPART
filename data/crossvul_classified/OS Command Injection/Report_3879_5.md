# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3879_5
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3879_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 130-173 of the vulnerable file.

                                <div class="col-xs-1">
                                    <label><!-- just a spacer for a nice layout --> &nbsp;</label>
                                    <br/>
                                    <a class="btn btn-default btn-sx txt-color-red deleteCommandArg"
                                       href="javascript:void(0);" delete="<?php echo $commandarg['id']; ?>">
                                        <i class="fa fa-trash-o fa-lg"></i>
                                    </a>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <div class="col-xs-12 padding-top-10">
                        <a class="btn btn-success btn-xs pull-right" id="add_new_arg" href="javascript:void(0);">
                            <i class="fa fa-plus"></i>
                            <?php echo __('Add argument'); ?>
                        </a>
                    </div>
                    <span class="col col-md-10 col-xs-12 txt-color-redLight"><i
                                class="fa fa-exclamation-circle"></i> <?php echo __('empty arguments will be removed automatically'); ?></span>
                </fieldset>
                <?php if ($this->Acl->hasPermission('terminal')): ?>
                    <br/>
                    <div id="console"></div>
                <?php endif; ?>
                <br/>
                <?php echo $this->Form->formActions(); ?>
            </div>
        </div>
    </div>

<?php if ($this->Acl->hasPermission('index', 'macros')): ?>
    <div class="modal fade" id="MacrosOverview" tabindex="-1" role="dialog" aria-labelledby="myModalLabel"
         aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
                        &times;
                    </button>
                    <h4 class="modal-title" id="myModalLabel"><?php echo __('User defined macros'); ?></h4>
                </div>
                <div class="modal-body">

                    <div class="row">
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -147,10 +147,6 @@
                     <span class="col col-md-10 col-xs-12 txt-color-redLight"><i
                                 class="fa fa-exclamation-circle"></i> <?php echo __('empty arguments will be removed automatically'); ?></span>
                 </fieldset>
-                <?php if ($this->Acl->hasPermission('terminal')): ?>
-                    <br/>
-                    <div id="console"></div>
-                <?php endif; ?>
                 <br/>
                 <?php echo $this->Form->formActions(); ?>
             </div>
```
