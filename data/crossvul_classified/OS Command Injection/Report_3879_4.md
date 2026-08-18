# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in php
**Pair ID:** 3879_4
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3879_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```php
Lines 87-130 of the vulnerable file.

                <?php echo __('Nagios supports up to 32 $ARGx$ macros ($ARG1$ through $ARG32$)'); ?>
            </div>
            <br/><br/>
            <?php echo $this->Form->input('description', ['label' => __('Description')]); ?>
            <fieldset class=" form-inline required padding-10">
                <legend class="font-sm">
                    <div>
                        <label><?php echo __('Arguments'); ?>:</label>
                    </div>
                </legend>
                <div id="command_args">
                    <!-- empty because we create a new command! -->
                </div>
                <div class="col-xs-12 padding-top-10">
                    <a class="btn btn-success btn-xs pull-right" id="add_new_arg" href="javascript:void(0);">
                        <i class="fa fa-plus"></i>
                        <?php echo __('Add argument'); ?>
                    </a>
                </div>
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
@@ -104,10 +104,6 @@
                     </a>
                 </div>
             </fieldset>
-            <?php if ($this->Acl->hasPermission('terminal')): ?>
-                <br/>
-                <div id="console"></div>
-            <?php endif; ?>
             <br/>
             <?php echo $this->Form->formActions(); ?>
         </div>
```
