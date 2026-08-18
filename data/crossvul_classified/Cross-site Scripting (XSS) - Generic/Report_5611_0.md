# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5611_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5611_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 93-133 of the vulnerable file.

    PMA_GIS_saveToFile($data, $visualizationSettings, $save_format, $file_name);
    exit();
}

$svg_support = (PMA_USR_BROWSER_AGENT == 'IE' && PMA_USR_BROWSER_VER <= 8) ? false : true;
$format = $svg_support ? 'svg' : 'png';

// get the chart and settings after chart generation
$visualization = PMA_GIS_visualizationResults($data, $visualizationSettings, $format);

/**
 * Displays the page
 */
?>
<!-- Display visulalization options -->
<div id="div_view_options">
<form method="post" action="tbl_gis_visualization.php">
<?php echo PMA_generate_common_hidden_inputs($url_params); ?>
<fieldset>
    <legend><?php echo __('Display GIS Visualization'); ?></legend>
    <div id="placeholder" style="width:<?php echo($visualizationSettings['width']); ?>px;height:<?php echo($visualizationSettings['height']); ?>px;">
        <?php echo $visualization; ?>
    </div>
    <div id="openlayersmap"></div>
    <input type="hidden" id="pmaThemeImage" value="<?php echo($GLOBALS['pmaThemeImage']); ?>" />

    <script language="javascript" type="text/javascript">
        function drawOpenLayers() {
            <?php echo (PMA_GIS_visualizationResults($data, $visualizationSettings, 'ol')); ?>
        }
    </script>

    <input type="hidden" name="sql_query" id="sql_query" value="<?php echo htmlspecialchars($sql_query); ?>" />

    <table class="gis_table">
    <tr><td><label for="width"><?php echo __("Width"); ?></label></td>
        <td><input type="text" name="visualizationSettings[width]" id="width" value="<?php echo (isset($visualizationSettings['width']) ? htmlspecialchars($visualizationSettings['width']) : ''); ?>" /></td>
    </tr>

    <tr><td><label for="height"><?php echo __("Height"); ?></label></td>
        <td><input type="text" name="visualizationSettings[height]" id="height" value="<?php echo (isset($visualizationSettings['height']) ? htmlspecialchars($visualizationSettings['height']) : ''); ?>" /></td>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,7 @@
 <?php echo PMA_generate_common_hidden_inputs($url_params); ?>
 <fieldset>
     <legend><?php echo __('Display GIS Visualization'); ?></legend>
-    <div id="placeholder" style="width:<?php echo($visualizationSettings['width']); ?>px;height:<?php echo($visualizationSettings['height']); ?>px;">
+    <div id="placeholder" style="width:<?php echo(htmlspecialchars($visualizationSettings['width'])); ?>px;height:<?php echo(htmlspecialchars($visualizationSettings['height'])); ?>px;">
         <?php echo $visualization; ?>
     </div>
     <div id="openlayersmap"></div>
```
