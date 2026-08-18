# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3977_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3977_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 329-370 of the vulnerable file.

              if (isset($cInfo) && is_object($cInfo) && ($advert['advert_id'] == $cInfo->advert_id)) {
                echo '<tr class="table-active">';
              } else {
                echo '<tr onclick="document.location.href=\'' . tep_href_link('advert_manager.php', 'page=' . (int)$_GET['page'] . '&cID=' . (int)$advert['advert_id']) . '\'">';
              }
?>
                <td><?php echo $advert['advert_title']; ?></td>
                <td class="text-right"><?php echo $advert['advert_group']; ?></td>
                <td class="text-right"><?php echo $advert['sort_order'] ?? 0; ?></td>
                <td class="text-right"><?php if ($advert['status'] == '1') { echo '<i class="fas fa-check-circle text-success"></i> <a href="' . tep_href_link('advert_manager.php', 'page=' . (int)$_GET['page'] . '&cID=' . (int)$advert['advert_id'] . '&action=setflag&flag=0') . '"><i class="fas fa-times-circle text-muted"></i></a>'; } else { echo '<a href="' . tep_href_link('advert_manager.php', 'page=' . (int)$_GET['page'] . '&cID=' . $advert['advert_id'] . '&action=setflag&flag=1') . '"><i class="fas fa-check-circle text-muted"></i></a> <i class="fas fa-times-circle text-danger"></i>'; } ?></td>
                <td class="text-right"><?php if (isset($cInfo) && is_object($cInfo) && ($advert['advert_id'] == $cInfo->advert_id)) { echo '<i class="fas fa-chevron-circle-right text-info"></i>'; } else { echo '<a href="' . tep_href_link('advert_manager.php', 'page=' . (int)$_GET['page'] . '&cID=' . $advert['advert_id']) . '"><i class="fas fa-info-circle text-muted"></i></a>'; } ?></td>
              </tr>
              <?php
            }
            ?>
          </tbody>
        </table>
      </div>

      <div class="row my-1">
        <div class="col"><?php echo $advert_split->display_count($advert_query_numrows, MAX_DISPLAY_SEARCH_RESULTS, (int)$_GET['page'], TEXT_DISPLAY_NUMBER_OF_ADVERTS); ?></div>
        <div class="col text-right mr-2"><?php echo $advert_split->display_links($advert_query_numrows, MAX_DISPLAY_SEARCH_RESULTS, MAX_DISPLAY_PAGE_LINKS, (int)$_GET['page']); ?></div>
      </div>

      <?php
      $banner_table_query = tep_db_query("SHOW TABLES LIKE 'banners'");
      if ($advert_query_numrows == 0 && tep_db_num_rows($banner_table_query)) {
        echo '<div class="alert alert-info mt-3">';
          echo '<div class="row align-items-center">';
            echo '<div class="col-4">';
              echo tep_draw_bootstrap_button(IMAGE_IMPORT_ADVERT, 'fas fa-database', tep_href_link('advert_manager.php', 'action=import'), null, null, 'btn-info btn-block xxx text-white');
            echo '</div>';
            echo '<div class="col">';
              echo IMAGE_IMPORT_ADVERT_EXPLANATION;
            echo '</div>';
          echo '</div>';
        echo '</div>';
      }
      ?>

    </div>

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -346,8 +346,8 @@
       </div>
 
       <div class="row my-1">
-        <div class="col"><?php echo $advert_split->display_count($advert_query_numrows, MAX_DISPLAY_SEARCH_RESULTS, (int)$_GET['page'], TEXT_DISPLAY_NUMBER_OF_ADVERTS); ?></div>
-        <div class="col text-right mr-2"><?php echo $advert_split->display_links($advert_query_numrows, MAX_DISPLAY_SEARCH_RESULTS, MAX_DISPLAY_PAGE_LINKS, (int)$_GET['page']); ?></div>
+        <div class="col"><?php echo $advert_split->display_count($advert_query_numrows, MAX_DISPLAY_SEARCH_RESULTS, $_GET['page'], TEXT_DISPLAY_NUMBER_OF_ADVERTS); ?></div>
+        <div class="col text-right mr-2"><?php echo $advert_split->display_links($advert_query_numrows, MAX_DISPLAY_SEARCH_RESULTS, MAX_DISPLAY_PAGE_LINKS, $_GET['page']); ?></div>
       </div>
 
       <?php
```
