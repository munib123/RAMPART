# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 302_7
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `302_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 92-132 of the vulnerable file.

        <th scope="row"><label for="nw_top">팝업레이어 상단 위치<strong class="sound_only"> 필수</strong></label></th>
        <td>
            <input type="text" name="nw_top" value="<?php echo $nw['nw_top']; ?>" id="nw_top" required class="frm_input required"  size="5"> px
        </td>
    </tr>
    <tr>
        <th scope="row"><label for="nw_width">팝업레이어 넓이<strong class="sound_only"> 필수</strong></label></th>
        <td>
            <input type="text" name="nw_width" value="<?php echo $nw['nw_width'] ?>" id="nw_width" required class="frm_input required" size="5"> px
        </td>
    </tr>
    <tr>
        <th scope="row"><label for="nw_height">팝업레이어 높이<strong class="sound_only"> 필수</strong></label></th>
        <td>
            <input type="text" name="nw_height" value="<?php echo $nw['nw_height'] ?>" id="nw_height" required class="frm_input required" size="5"> px
        </td>
    </tr>
    <tr>
        <th scope="row"><label for="nw_subject">팝업 제목<strong class="sound_only"> 필수</strong></label></th>
        <td>
            <input type="text" name="nw_subject" value="<?php echo stripslashes($nw['nw_subject']) ?>" id="nw_subject" required class="frm_input required" size="80">
        </td>
    </tr>
    <tr>
        <th scope="row"><label for="nw_content">내용</label></th>
        <td><?php echo editor_html('nw_content', get_text($nw['nw_content'], 0)); ?></td>
    </tr>
    </tbody>
    </table>
</div>

<div class="btn_fixed_top">
    <a href="./newwinlist.php" class=" btn btn_02">목록</a>
    <input type="submit" value="확인" class="btn_submit btn" accesskey="s">
</div>
</form>

<script>
function frmnewwin_check(f)
{
    errmsg = "";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -109,7 +109,7 @@
     <tr>
         <th scope="row"><label for="nw_subject">팝업 제목<strong class="sound_only"> 필수</strong></label></th>
         <td>
-            <input type="text" name="nw_subject" value="<?php echo stripslashes($nw['nw_subject']) ?>" id="nw_subject" required class="frm_input required" size="80">
+            <input type="text" name="nw_subject" value="<?php echo get_sanitize_input($nw['nw_subject']); ?>" id="nw_subject" required class="frm_input required" size="80">
         </td>
     </tr>
     <tr>
```
