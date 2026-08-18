# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 4210_1
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4210_1`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 9-49 of the vulnerable file.

 * @since			baserCMS v 4.0.0
 * @license			https://basercms.net/license/index.html
 */

/**
 * サブサイト一覧（行）
 */
$classies = [];
if ($data['Site']['status']) {
	$classies = ['publish'];
} else {
	$classies = ['unpublish', 'disablerow'];
}
$class = ' class="' . implode(' ', $classies) . '"';
$url = $this->BcContents->getUrl('/' . $data['Site']['alias'] . '/', true, $data['Site']['use_subdomain']);
?>


<tr id="Row<?php echo $count ?>" <?php echo $class; ?>>
	<td class="bca-table-listup__tbody-td" style="width:5%"><?php echo $data['Site']['id']; ?></td>
	<td class="bca-table-listup__tbody-td"><?php echo $data['Site']['display_name'] ?></td>
	<td class="bca-table-listup__tbody-td"><?php $this->BcBaser->link($data['Site']['name'], ['action' => 'edit', $data['Site']['id']]); ?><br>
		<?php echo $data['Site']['alias'] ?>
	</td>
	<td class="bca-table-listup__tbody-td" style="width:5%;" class="bc-align-center status">
		<?php echo $this->BcText->booleanMark($data['Site']['status']); ?><br>
	</td>
	<td class="bca-table-listup__tbody-td" class="bc-align-center">
		<?php echo $this->BcText->arrayValue($data['Site']['device'], $devices, ''); ?><br>
		<?php echo $this->BcText->arrayValue($data['Site']['lang'], $langs, ''); ?>
	</td>
	<td class="bca-table-listup__tbody-td"><?php echo $this->BcText->arrayValue($data['Site']['main_site_id'], $mainSites, ''); ?><br>
		<?php echo $this->BcText->noValue($data['Site']['theme'], $this->BcBaser->siteConfig['theme']) ?>
	</td>
	<?php echo $this->BcListTable->dispatchShowRow($data) ?>
	<td class="bca-table-listup__tbody-td" style="width:10%;white-space: nowrap">
		<?php echo $this->BcTime->format('Y-m-d', $data['Site']['created']) ?><br>
		<?php echo $this->BcTime->format('Y-m-d', $data['Site']['modified']) ?>
	</td>
	<td class="row-tools bca-table-listup__tbody-td bca-table-listup__tbody-td--actions" style="width:15%">
		<?php $this->BcBaser->link('', ['action' => 'ajax_unpublish', $data['Site']['id']], ['title' => __d('baser', '非公開'), 'class' => 'btn-unpublish bca-btn-icon', 'data-bca-btn-type' => 'unpublish','data-bca-btn-size' => 'lg']) ?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -26,7 +26,7 @@
 
 <tr id="Row<?php echo $count ?>" <?php echo $class; ?>>
 	<td class="bca-table-listup__tbody-td" style="width:5%"><?php echo $data['Site']['id']; ?></td>
-	<td class="bca-table-listup__tbody-td"><?php echo $data['Site']['display_name'] ?></td>
+	<td class="bca-table-listup__tbody-td"><?php echo h($data['Site']['display_name']) ?></td>
 	<td class="bca-table-listup__tbody-td"><?php $this->BcBaser->link($data['Site']['name'], ['action' => 'edit', $data['Site']['id']]); ?><br>
 		<?php echo $data['Site']['alias'] ?>
 	</td>
```
