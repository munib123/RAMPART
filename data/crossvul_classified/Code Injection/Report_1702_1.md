# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in php
**Pair ID:** 1702_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1702_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```php
Lines 12-52 of the vulnerable file.

	</tr><?php
foreach ($attributes as $item):?>
	<tr>
		<td><?php echo h($item['category']); ?></td>
		<td><?php echo h($item['type']); ?></td>
		<td><?php echo h($item['value']); ?></td>
		<td><?php echo h($item['comment']); ?></td>
		<td><?php echo ($item['to_ids'] ? 'Yes' : 'No'); ?></td>
		<td><?php echo $distributionLevels[$item['distribution']]; ?></td>
	</tr><?php
endforeach;?>
	</table>
	<div style="float:left;">
		<?php echo $this->Form->create('Template', array('url' => '/templates/submitEventPopulation/' . $template_id . '/' . $event_id));?>
			<fieldset>
				<?php 
					echo $this->Form->input('attributes', array(
							'id' => 'attributes',
							'label' => false,
							'type' => 'hidden',
							'value' => serialize($attributes),
					));
				?>
			</fieldset>
		<?php
		echo $this->Form->button('Finalise', array('class' => 'btn btn-primary'));
		echo $this->Form->end();
		?>
	</div>
	<div style="float:left;width:10px;">&nbsp;</div>
	<div>
		<?php echo $this->Form->create('Template');?>
			<fieldset>
				<?php 
					foreach ($template['Template'] as $k => $v) {
						if (strpos($k, 'ile_')) $v = serialize($v);
						echo $this->Form->input($k, array(
							'label' => false,
							'type' => 'hidden',
							'value' => $v,
						));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -29,7 +29,7 @@
 							'id' => 'attributes',
 							'label' => false,
 							'type' => 'hidden',
-							'value' => serialize($attributes),
+							'value' => json_encode($attributes),
 					));
 				?>
 			</fieldset>
```
