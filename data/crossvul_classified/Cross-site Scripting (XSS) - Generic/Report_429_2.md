# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 429_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `429_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 1300-1340 of the vulnerable file.

    <?php echo $pg_anchor ?>
    <div class="local_desc02 local_desc">
        <p>각 게시판 관리에서 개별적으로 설정 가능합니다.</p>
    </div>

    <div class="tbl_frm01 tbl_wrap">
        <table>
        <caption>여분필드 기본 설정</caption>
        <colgroup>
            <col class="grid_4">
            <col>
        </colgroup>
        <tbody>
        <?php for ($i=1; $i<=10; $i++) { ?>
        <tr>
            <th scope="row">여분필드<?php echo $i ?></th>
            <td class="td_extra">
                <label for="cf_<?php echo $i ?>_subj">여분필드<?php echo $i ?> 제목</label>
                <input type="text" name="cf_<?php echo $i ?>_subj" value="<?php echo get_text($config['cf_'.$i.'_subj']) ?>" id="cf_<?php echo $i ?>_subj" class="frm_input" size="30">
                <label for="cf_<?php echo $i ?>">여분필드<?php echo $i ?> 값</label>
                <input type="text" name="cf_<?php echo $i ?>" value="<?php echo $config['cf_'.$i] ?>" id="cf_<?php echo $i ?>" class="frm_input" size="30">
            </td>
        </tr>
        <?php } ?>
        </tbody>
        </table>
    </div>
</section>

<div class="btn_fixed_top btn_confirm">
    <input type="submit" value="확인" class="btn_submit btn" accesskey="s">
</div>

</form>

<script>
$(function(){
    <?php
    if(!$config['cf_cert_use'])
        echo '$(".cf_cert_service").addClass("cf_cert_hide");';
    ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1317,7 +1317,7 @@
                 <label for="cf_<?php echo $i ?>_subj">여분필드<?php echo $i ?> 제목</label>
                 <input type="text" name="cf_<?php echo $i ?>_subj" value="<?php echo get_text($config['cf_'.$i.'_subj']) ?>" id="cf_<?php echo $i ?>_subj" class="frm_input" size="30">
                 <label for="cf_<?php echo $i ?>">여분필드<?php echo $i ?> 값</label>
-                <input type="text" name="cf_<?php echo $i ?>" value="<?php echo $config['cf_'.$i] ?>" id="cf_<?php echo $i ?>" class="frm_input" size="30">
+                <input type="text" name="cf_<?php echo $i ?>" value="<?php echo get_sanitize_input($config['cf_'.$i]); ?>" id="cf_<?php echo $i ?>" class="frm_input" size="30">
             </td>
         </tr>
         <?php } ?>
```
