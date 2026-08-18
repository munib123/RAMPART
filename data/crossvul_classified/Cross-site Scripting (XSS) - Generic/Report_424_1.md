# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 424_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `424_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 100-140 of the vulnerable file.

        </td>
    </tr>
    <tr>
        <th scope="row">접근회원수</th>
        <td>
            <?php
            // 접근회원수
            $sql1 = " select count(*) as cnt from {$g5['group_member_table']} where gr_id = '{$gr_id}' ";
            $row1 = sql_fetch($sql1);
            echo '<a href="./boardgroupmember_list.php?gr_id='.$gr_id.'">'.$row1['cnt'].'</a>';
            ?>
        </td>
    </tr>
    <?php for ($i=1;$i<=10;$i++) { ?>
    <tr>
        <th scope="row">여분필드<?php echo $i ?></th>
        <td class="td_extra">
            <label for="gr_<?php echo $i ?>_subj">여분필드 <?php echo $i ?> 제목</label>
            <input type="text" name="gr_<?php echo $i ?>_subj" value="<?php echo get_text($group['gr_'.$i.'_subj']) ?>" id="gr_<?php echo $i ?>_subj" class="frm_input">
            <label for="gr_<?php echo $i ?>">여분필드 <?php echo $i ?> 내용</label>
            <input type="text" name="gr_<?php echo $i ?>" value="<?php echo $gr['gr_'.$i] ?>" id="gr_<?php echo $i ?>" class="frm_input">
        </td>
    </tr>
    <?php } ?>
    </tbody>
    </table>
</div>

<div class="btn_fixed_top">
    <a href="./boardgroup_list.php?<?php echo $qstr ?>" class="btn btn_02">목록</a>
    <input type="submit" class="btn_submit btn" accesskey="s" value="확인">
</div>

</form>

<div class="local_desc01 local_desc">
    <p>
        게시판을 생성하시려면 1개 이상의 게시판그룹이 필요합니다.<br>
        게시판그룹을 이용하시면 더 효과적으로 게시판을 관리할 수 있습니다.
    </p>
</div>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -117,7 +117,7 @@
             <label for="gr_<?php echo $i ?>_subj">여분필드 <?php echo $i ?> 제목</label>
             <input type="text" name="gr_<?php echo $i ?>_subj" value="<?php echo get_text($group['gr_'.$i.'_subj']) ?>" id="gr_<?php echo $i ?>_subj" class="frm_input">
             <label for="gr_<?php echo $i ?>">여분필드 <?php echo $i ?> 내용</label>
-            <input type="text" name="gr_<?php echo $i ?>" value="<?php echo $gr['gr_'.$i] ?>" id="gr_<?php echo $i ?>" class="frm_input">
+            <input type="text" name="gr_<?php echo $i ?>" value="<?php echo get_sanitize_input($gr['gr_'.$i]); ?>" id="gr_<?php echo $i ?>" class="frm_input">
         </td>
     </tr>
     <?php } ?>
```
