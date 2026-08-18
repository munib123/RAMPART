# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 4210_4
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4210_4`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 4-41 of the vulnerable file.

 * Copyright (c) baserCMS Users Community <http://basercms.net/community/>
 *
 * @copyright		Copyright (c) baserCMS Users Community
 * @link			http://basercms.net baserCMS Project
 * @package			Feed.View
 * @since			baserCMS v 0.1.0
 * @license			http://basercms.net/license/index.html
 */

/**
 * [ADMIN] フィード設定　行
 * @var \BcAppView $this
 */
?>


<tr>
	<td class="row-tools">
		<?php if ($this->BcBaser->isAdminUser()): ?>
			<?php echo $this->BcForm->checkbox('ListTool.batch_targets.' . $data['id'], array('type' => 'checkbox', 'class' => 'batch-targets', 'value' => $data['id'])) ?>
		<?php endif ?>		
		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_check.png', array('alt' => __d('baser', '確認'), 'class' => 'btn')), $data['url'], array('title' => __d('baser', '確認'), 'target' => '_blank')) ?>
		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_edit.png', array('alt' => __d('baser', '編集'), 'class' => 'btn')), array('controller' => 'feed_details', 'action' => 'edit', $this->BcForm->value('FeedConfig.id'), $data['id']), array('title' => __d('baser', '編集'))) ?>
		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_delete.png', array('alt' => __d('baser', '削除'), 'class' => 'btn')), array('controller' => 'feed_details', 'action' => 'ajax_delete', $this->BcForm->value('FeedConfig.id'), $data['id']), array('title' => __d('baser', '削除'), 'class' => 'btn-delete')) ?>
	</td>
	<td>
		<?php if ($data['url']): ?>
			<?php $this->BcBaser->link($data['name'], array('controller' => 'feed_details', 'action' => 'edit', $this->BcForm->value('FeedConfig.id'), $data['id'])) ?>
		<?php else: ?>
			<?php echo $data['name'] ?>
		<?php endif; ?>
	</td>
	<td><?php echo $data['category_filter'] ?></td>
	<td><?php echo $this->BcText->listValue('FeedDetail.cache_time', $data['cache_time']) ?></td>
	<?php echo $this->BcListTable->dispatchShowRow($data) ?>
	<td><?php echo $this->BcTime->format('Y-m-d', $data['created']) ?><br />
		<?php echo $this->BcTime->format('Y-m-d', $data['modified']) ?></td>
</tr>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,16 +21,16 @@
 	<td class="row-tools">
 		<?php if ($this->BcBaser->isAdminUser()): ?>
 			<?php echo $this->BcForm->checkbox('ListTool.batch_targets.' . $data['id'], array('type' => 'checkbox', 'class' => 'batch-targets', 'value' => $data['id'])) ?>
-		<?php endif ?>		
+		<?php endif ?>
 		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_check.png', array('alt' => __d('baser', '確認'), 'class' => 'btn')), $data['url'], array('title' => __d('baser', '確認'), 'target' => '_blank')) ?>
 		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_edit.png', array('alt' => __d('baser', '編集'), 'class' => 'btn')), array('controller' => 'feed_details', 'action' => 'edit', $this->BcForm->value('FeedConfig.id'), $data['id']), array('title' => __d('baser', '編集'))) ?>
 		<?php $this->BcBaser->link($this->BcBaser->getImg('admin/icn_tool_delete.png', array('alt' => __d('baser', '削除'), 'class' => 'btn')), array('controller' => 'feed_details', 'action' => 'ajax_delete', $this->BcForm->value('FeedConfig.id'), $data['id']), array('title' => __d('baser', '削除'), 'class' => 'btn-delete')) ?>
 	</td>
 	<td>
 		<?php if ($data['url']): ?>
-			<?php $this->BcBaser->link($data['name'], array('controller' => 'feed_details', 'action' => 'edit', $this->BcForm->value('FeedConfig.id'), $data['id'])) ?>
+			<?php $this->BcBaser->link($data['name'], array('controller' => 'feed_details', 'action' => 'edit', $this->BcForm->value('FeedConfig.id'), $data['id']), ['escape' => true]) ?>
 		<?php else: ?>
-			<?php echo $data['name'] ?>
+			<?php echo h($data['name']) ?>
 		<?php endif; ?>
 	</td>
 	<td><?php echo $data['category_filter'] ?></td>
```
