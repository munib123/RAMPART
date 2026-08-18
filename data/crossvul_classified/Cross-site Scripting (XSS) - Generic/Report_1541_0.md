# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 1541_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1541_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 48-69 of the vulnerable file.

        <div><span><?php echo lang('mobile phone number') ?>:</span> <?php echo clean($contact->getMobileNumber()) ?></div>
  <?php } // if ?>
  <?php if (trim($contact->getHomeNumber()) != '') { ?>
        <div><span><?php echo lang('home phone number') ?>:</span> <?php echo clean($contact->getHomeNumber()) ?></div>
  <?php } // if ?>
      </div>
  <?php if ($company->hasAddress()) { ?>
      <div class="companyInfo">
        <span><?php echo lang('address') ?>:</span><br/>
        <?php echo $company->getAddress().', '.$company->getAddress2(); ?><br/>
        <?php echo $company->getCity().', '.$company->getState().' '.$company->getZipcode(); ?>
      </div>
  <?php } // if ?>
      <div class="clear"></div>
    </div>
    <div class="clear"></div>
  </div>
<?php } // foreach ?>
</div>
<?php } else { ?>
  <div><?php echo lang('no search result for', $search_term) ?></div>
<?php } // if ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,5 +65,5 @@
 <?php } // foreach ?>
 </div>
 <?php } else { ?>
-  <div><?php echo lang('no search result for', $search_term) ?></div>
+  <div><?php echo lang('no search result for', clean($search_term)) ?></div>
 <?php } // if ?>
```
