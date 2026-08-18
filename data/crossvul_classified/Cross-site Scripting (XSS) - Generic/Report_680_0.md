# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 680_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `680_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 126-167 of the vulnerable file.

						}
					?>
				</select>
			</td>
			<td class="short">
				<?php
					$divVisibility = '';
					$selectVisibility = '';
					if (count($item['types']) == 1) {
						$selectVisibility = 'display:none;';
					} else {
						$divVisibility = 'style="display:none;"';
						if (!in_array(array_keys($item['types']), $options)) $options[] = array_values($item['types']);
					}
				?>
				<div id = "<?php echo 'Attribute' . $k . 'TypeStatic'; ?>" <?php echo $divVisibility; ?> ><?php echo h($item['default_type']); ?></div>
				<select id = "<?php echo 'Attribute' . $k . 'Type'; ?>" class='typeToggle' style='padding:0px;height:20px;margin-bottom:0px;<?php echo $selectVisibility; ?>'>
					<?php
						if (!empty($item['types'])) {
							foreach ($item['types'] as $type) {
								echo '<option value="' . $type . '" ';
								echo ($type == $item['default_type'] ? 'selected="selected"' : '') . '>' . $type . '</option>';
							}
						}
					?>
				</select>
			</td>
			<td class="short" style="width:40px;text-align:center;">
				<input type="checkbox" id="<?php echo 'Attribute' . $k . 'To_ids'; ?>" <?php if ($item['to_ids']) echo 'checked'; ?> class="idsCheckbox" />
			</td>
			<td class="short" style="width:40px;text-align:center;">
				<select id = "<?php echo 'Attribute' . $k . 'Distribution'; ?>" class='distributionToggle' style='padding:0px;height:20px;margin-bottom:0px;'>
					<?php
						foreach ($distributions as $distKey => $distValue) {
							$default = isset($item['distribution']) ? $item['distribution'] : $instanceDefault;
							echo '<option value="' . $distKey . '" ';
							echo ($distKey == $default ? 'selected="selected"' : '') . '>' . $distValue . '</option>';
						}
					?>
				</select>
				<div style="display:none;">
					<select id = "<?php echo 'Attribute' . $k . 'SharingGroupId'; ?>" class='sgToggle' style='padding:0px;height:20px;margin-top:3px;margin-bottom:0px;'>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -143,8 +143,8 @@
 					<?php
 						if (!empty($item['types'])) {
 							foreach ($item['types'] as $type) {
-								echo '<option value="' . $type . '" ';
-								echo ($type == $item['default_type'] ? 'selected="selected"' : '') . '>' . $type . '</option>';
+								echo '<option value="' . h($type) . '" ';
+								echo ($type == $item['default_type'] ? 'selected="selected"' : '') . '>' . h($type) . '</option>';
 							}
 						}
 					?>
@@ -167,17 +167,17 @@
 					<select id = "<?php echo 'Attribute' . $k . 'SharingGroupId'; ?>" class='sgToggle' style='padding:0px;height:20px;margin-top:3px;margin-bottom:0px;'>
 						<?php
 							foreach ($sgs as $sgKey => $sgValue) {
-								echo '<option value="' . $sgKey . '">' . $sgValue . '</option>';
+								echo '<option value="' . h($sgKey) . '">' . h($sgValue) . '</option>';
 							}
 						?>
 					</select>
 				</div>
 			</td>
 			<td class="short">
-				<input type="text" class="freetextCommentField" id="<?php echo 'Attribute' . $k . 'Comment'; ?>" style="padding:0px;height:20px;margin-bottom:0px;" placeholder="<?php echo h($importComment); ?>" <?php if (isset($item['comment']) && $item['comment'] !== false) echo 'value="' . $item['comment'] . '"'?>/>
-			</td>
-			<td class="short">
-				<input type="text" class="freetextTagField" id="<?php echo 'Attribute' . $k . 'Tags'; ?>" style="padding:0px;height:20px;margin-bottom:0px;"<?php if (isset($item['tags']) && $item['tags'] !== false) echo 'value="' . htmlspecialchars(implode(",",$item['tags'])) . '"'?>/>
+				<input type="text" class="freetextCommentField" id="<?php echo 'Attribute' . $k . 'Comment'; ?>" style="padding:0px;height:20px;margin-bottom:0px;" placeholder="<?php echo h($importComment); ?>" <?php if (isset($item['comment']) && $item['comment'] !== false) echo 'value="' . h($item['comment']) . '"'?>/>
+			</td>
+			<td class="short">
+				<input type="text" class="freetextTagField" id="<?php echo 'Attribute' . $k . 'Tags'; ?>" style="padding:0px;height:20px;margin-bottom:0px;"<?php if (isset($item['tags']) && $item['tags'] !== false) echo 'value="' . h(implode(",",$item['tags'])) . '"'?>/>
 			</td>
 			<td class="action short">
 				<span class="icon-remove pointer" title="<?php echo __('Remove resolved attribute');?>" role="button" tabindex="0" aria-label="<?php echo __('Remove resolved attribute');?>" onClick="freetextRemoveRow('<?php echo $k; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
@@ -206,7 +206,7 @@
 					<?php
 						foreach (array_keys($optionsRearranged) as $fromElement):
 					?>
-							<option><?php echo $fromElement; ?></option>
+							<option><?php echo h($fromElement); ?></option>
 					<?php
 						endforeach;
 					?>
```
