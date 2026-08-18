# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3408_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3408_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 84-124 of the vulnerable file.

																'client'	=> $url_client_id,
																'category'	=> $category['id'],
															);
										$link_query	= http_build_query($link_data);
								?>
										<li><a href="<?php echo $link_template . '?' . $link_query; ?>"><?php echo $category['name']; ?></a></li>
								<?php
									}
								?>							
							</ul>
						</nav>
				<?php
					}
				?>
			</div>
		</div>

		<header>
			<?php if ($logo_file_info['exists'] === true) { ?>
				<div id="logo">
					<img src="<?php echo TIMTHUMB_URL; ?>?src=<?php echo $logo_file_info['url']; ?>&amp;w=<?php echo LOGO_MAX_WIDTH; ?>" alt="<?php echo THIS_INSTALL_SET_TITLE; ?>" />
				</div>
			<?php } ?>
		</header>
			
		<div id="content">
		
			<?php
				if (!$count) {
					_e('There are no files.','cftp_template_gallery');
				}
				else {
			?>
					<ul class="photo_list">
						<?php
							foreach ($img_files as $this_file) {
								$download_link = make_download_link($this_file);
						?>
								<li>
									<h5><?php echo htmlentities($this_file['name']); ?></h5>
									<?php
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,7 +101,7 @@
 		<header>
 			<?php if ($logo_file_info['exists'] === true) { ?>
 				<div id="logo">
-					<img src="<?php echo TIMTHUMB_URL; ?>?src=<?php echo $logo_file_info['url']; ?>&amp;w=<?php echo LOGO_MAX_WIDTH; ?>" alt="<?php echo THIS_INSTALL_SET_TITLE; ?>" />
+					<img src="<?php echo TIMTHUMB_URL; ?>?src=<?php echo $logo_file_info['url']; ?>&amp;w=<?php echo LOGO_MAX_WIDTH; ?>" alt="<?php echo html_output(THIS_INSTALL_SET_TITLE); ?>" />
 				</div>
 			<?php } ?>
 		</header>
```
