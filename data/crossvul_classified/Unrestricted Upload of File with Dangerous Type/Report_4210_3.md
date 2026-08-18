# CrossVul Fix Pair: Unrestricted Upload of File with Dangerous Type in php
**Pair ID:** 4210_3
**Vulnerability Class:** Unrestricted Upload of File with Dangerous Type
**CWE:** CWE-434
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4210_3`)

## Vulnerability Information & PoC

## Description
Unrestricted Upload of File with Dangerous Type - The product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.

## Vulnerable Code
```php
Lines 41-81 of the vulnerable file.

<?php echo $this->BcForm->label('WidgetArea.name', __d('baser', 'ウィジェットエリア名')) ?>&nbsp;
<?php echo $this->BcForm->input('WidgetArea.name', ['type' => 'text', 'size' => 40, 'autofocus' => true]) ?>&nbsp;
<span class="submit"><?php echo $this->BcForm->end(['label' => __d('baser', 'エリア名を保存する'), 'div' => false, 'class' => 'button btn-red bca-btn', 'id' => 'WidgetAreaUpdateTitleSubmit', 'data-bca-btn-type' => 'save']) ?></span>
<?php $this->BcBaser->img('admin/ajax-loader-s.gif', ['style' => 'vertical-align:middle;display:none', 'id' => 'WidgetAreaUpdateTitleLoader']) ?>
<?php echo $this->BcForm->error('WidgetArea.name') ?>

<?php if (!empty($widgetInfos)): ?>

	<?php echo $this->BcForm->create('WidgetArea', ['url' => ['action' => 'update_sort', $this->BcForm->value('WidgetArea.id'), 'id' => false]]) ?>
	<?php echo $this->BcForm->input('WidgetArea.sorted_ids', ['type' => 'hidden']) ?>
	<?php echo $this->BcForm->end() ?>

	<div id="WidgetSetting" class="clearfix" >

		<!-- 利用できるウィジェット -->
		<div id="SourceOuter">
			<div id="Source">

				<h2><?php echo __d('baser', '利用できるウィジェット') ?></h2>
				<?php foreach ($widgetInfos as $widgetInfo) : ?>
					<h3><?php echo $widgetInfo['title'] ?></h3>
					<?php
					$widgets = [];
					foreach ($widgetInfo['paths'] as $path) {
						$Folder = new Folder($path);
						$files = $Folder->read(true, true, true);
						$widgets = [];
						foreach ($files[1] as $file) {
							$widget = ['name' => '', 'title' => '', 'description' => '', 'setting' => ''];
							ob_start();
							$key = 'Widget';
							// タイトルや説明文を取得する為、elementを使わず、includeする。
							// コントローラーでインクルードした場合、コントローラー内でヘルパ等が読み込まれていないのが原因で
							// エラーとなるのでここで読み込む
							include $file;
							$widget['name'] = basename($file, $this->ext);
							$widget['title'] = $title;
							$widget['description'] = $description;
							$widget['setting'] = ob_get_contents();
							$widgets[] = $widget;
							ob_end_clean();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,7 +58,7 @@
 
 				<h2><?php echo __d('baser', '利用できるウィジェット') ?></h2>
 				<?php foreach ($widgetInfos as $widgetInfo) : ?>
-					<h3><?php echo $widgetInfo['title'] ?></h3>
+					<h3><?php echo h($widgetInfo['title']) ?></h3>
 					<?php
 					$widgets = [];
 					foreach ($widgetInfo['paths'] as $path) {
@@ -85,20 +85,20 @@
 					<?php foreach ($widgets as $widget): ?>
 
 						<div class="ui-widget-content draggable widget" id="Widget<?php echo Inflector::camelize($widget['name']) ?>">
-							<div class="head"><?php echo $widget['title'] ?></div>
+							<div class="head"><?php echo h($widget['title']) ?></div>
 						</div>
 
-						<div class="description"><?php echo $widget['description'] ?></div>
+						<div class="description"><?php echo h($widget['description']) ?></div>
 
-						<div class="ui-widget-content sortable widget template <?php echo $widget['name'] ?>" id="<?php echo Inflector::camelize($widget['name']) ?>">
+						<div class="ui-widget-content sortable widget template <?php echo h($widget['name']) ?>" id="<?php echo Inflector::camelize($widget['name']) ?>">
 							<div class="clearfix">
-								<div class="widget-name display-none"><?php echo $widget['name'] ?></div>
+								<div class="widget-name display-none"><?php echo h($widget['name']) ?></div>
 								<div class="del"><?php echo __d('baser', '削除') ?></div>
 								<div class="action"><?php echo __d('baser', '設定') ?></div>
-								<div class="head"><?php echo $widget['title'] ?></div>
+								<div class="head"><?php echo h($widget['title']) ?></div>
 							</div>
 							<div class="content" style="text-align:right">
-								<p class="widget-name"><small><?php echo $widget['title'] ?></small></p>
+								<p class="widget-name"><small><?php echo h($widget['title']) ?></small></p>
 								<?php echo $this->BcForm->create('Widget', ['url' => ['controller' => 'widget_areas', 'action' => 'update_widget', $this->BcForm->value('WidgetArea.id')], 'class' => 'form']) ?>
 								<?php echo $this->BcForm->input('Widget.id', ['type' => 'hidden', 'class' => 'id']) ?>
 								<?php echo $this->BcForm->input('Widget.type', ['type' => 'hidden', 'value' => $widget['title']]) ?>
@@ -134,15 +134,15 @@
 						<?php $key = key($widget) ?>
 						<?php $enabled = '' ?>
 						<?php if ($widget[$key]['status']): ?>
-				<?php $enabled = ' enabled' ?>
-			<?php endif ?>
+							<?php $enabled = ' enabled' ?>
+						<?php endif ?>
 
-						<div class="ui-widget-content sortable widget setting <?php echo $widget[$key]['element'] ?><?php echo $enabled ?>" id="Setting<?php echo $widget[$key]['id'] ?>">
+						<div class="ui-widget-content sortable widget setting <?php echo h($widget[$key]['element']) ?><?php echo $enabled ?>" id="Setting<?php echo $widget[$key]['id'] ?>">
 							<div class="clearfix">
-								<div class="widget-name display-none"><?php echo $widget[$key]['element'] ?></div>
+								<div class="widget-name display-none"><?php echo h($widget[$key]['element']) ?></div>
 								<div class="del"><?php echo __d('baser', '削除') ?></div>
 								<div class="action"><?php echo __d('baser', '設定') ?></div>
-								<div class="head"><?php echo $widget[$key]['name'] ?></div>
+								<div class="head"><?php echo h($widget[$key]['name']) ?></div>
 							</div>
 							<div class="content" style="text-align:right">
 								<p><small><?php echo $widget[$key]['type'] ?></small></p>
@@ -161,8 +161,8 @@
 								<?php echo $this->BcForm->end(['label' => __d('baser', '保存'), 'div' => false, 'id' => 'WidgetUpdateWidgetSubmit' . $widget[$key]['id'], 'class' => 'button bca-btn', 'data-bca-btn-type' => 'save']) ?></p>
 							</div>
 						</div>
-		<?php endforeach; ?>
-	<?php endif; ?>
+					<?php endforeach; ?>
+				<?php endif; ?>
 			</div>
 		</div>
 	</div>
```
