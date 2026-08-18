# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in php
**Pair ID:** 3283_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3283_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```php
Lines 392-433 of the vulnerable file.

					'link' => "index.php?module=config-smilies&amp;action=mass_edit"
				);

				$page->output_nav_tabs($sub_tabs, 'add_multiple_smilies');
				$form = new Form("index.php?module=config-smilies&amp;action=add_multiple", "post", "add_multiple");
				echo $form->generate_hidden_field("step", "2");
				echo $form->generate_hidden_field("pathfolder", $path);

				$form_container = new FormContainer($lang->add_multiple_smilies);
				$form_container->output_row_header($lang->image, array("class" => "align_center", 'width' => '10%'));
				$form_container->output_row_header($lang->name);
				$form_container->output_row_header($lang->text_replace, array('width' => '20%'));
				$form_container->output_row_header($lang->include, array("class" => "align_center", 'width' => '5%'));

				foreach($smilies as $key => $file)
				{
					$ext = get_extension($file);
					$find = str_replace(".".$ext, "", $file);
					$name = ucfirst($find);

					$form_container->output_cell("<img src=\"../".$path.$file."\" alt=\"\" /><br /><small>{$file}</small>", array("class" => "align_center", "width" => 1));
					$form_container->output_cell($form->generate_text_box("name[{$file}]", $name, array('id' => 'name', 'style' => 'width: 98%')));
					$form_container->output_cell($form->generate_text_box("find[{$file}]", ":".$find.":", array('id' => 'find', 'style' => 'width: 95%')));
					$form_container->output_cell($form->generate_check_box("include[{$file}]", 1, "", array('checked' => 1)), array("class" => "align_center"));
					$form_container->construct_row();
				}

				if($form_container->num_rows() == 0)
				{
					flash_message($lang->error_no_images, 'error');
					admin_redirect("index.php?module=config-smilies&action=add_multiple");
				}

				$form_container->end();

				$buttons[] = $form->generate_submit_button($lang->save_smilies);

				$form->output_submit_wrapper($buttons);
				$form->end();

				$page->output_footer();
				exit;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -409,8 +409,10 @@
 					$find = str_replace(".".$ext, "", $file);
 					$name = ucfirst($find);
 
-					$form_container->output_cell("<img src=\"../".$path.$file."\" alt=\"\" /><br /><small>{$file}</small>", array("class" => "align_center", "width" => 1));
-					$form_container->output_cell($form->generate_text_box("name[{$file}]", $name, array('id' => 'name', 'style' => 'width: 98%')));
+					$file = htmlspecialchars_uni($file);
+
+					$form_container->output_cell("<img src=\"../".htmlspecialchars_uni($path).$file."\" alt=\"\" /><br /><small>{$file}</small>", array("class" => "align_center", "width" => 1));
+					$form_container->output_cell($form->generate_text_box("name[{$file}]", htmlspecialchars_uni($name), array('id' => 'name', 'style' => 'width: 98%')));
 					$form_container->output_cell($form->generate_text_box("find[{$file}]", ":".$find.":", array('id' => 'find', 'style' => 'width: 95%')));
 					$form_container->output_cell($form->generate_check_box("include[{$file}]", 1, "", array('checked' => 1)), array("class" => "align_center"));
 					$form_container->construct_row();
@@ -645,11 +647,11 @@
 		$smilie['image'] = str_replace("{theme}", "images", $smilie['image']);
 		if(my_validate_url($smilie['image'], true))
 		{
-			$image = $smilie['image'];
+			$image = htmlspecialchars_uni($smilie['image']);
 		}
 		else
 		{
-			$image = "../".$smilie['image'];
+			$image = "../".htmlspecialchars_uni($smilie['image']);
 		}
 
 		$form_container->output_cell("<img src=\"{$image}\" alt=\"\" />", array("class" => "align_center", "width" => 1));
@@ -728,11 +730,11 @@
 		$smilie['image'] = str_replace("{theme}", "images", $smilie['image']);
 		if(my_validate_url($smilie['image'], true))
 		{
-			$image = $smilie['image'];
+			$image = htmlspecialchars_uni($smilie['image']);
 		}
 		else
 		{
-			$image = "../".$smilie['image'];
+			$image = "../".htmlspecialchars_uni($smilie['image']);
 		}
 
 		$table->construct_cell("<img src=\"{$image}\" alt=\"\" class=\"smilie smilie_{$smilie['sid']}\" />", array("class" => "align_center"));
```
