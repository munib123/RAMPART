# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3408_4
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3408_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 66-106 of the vulnerable file.

					function open_menu() {
						$('.categories').addClass('visible');
						$('.categories').stop().slideDown();
						$('.content_cover').stop().fadeIn(200);
					}

					function close_menu() {
						$('.categories').removeClass('visible');
						$('.content_cover').stop().fadeOut(200);
						$('.categories').stop().slideUp();
					}
				}
			);
		</script>
	</head>
	
	<body>
		<div id="header">
			<?php if ($logo_file_info['exists'] === true) { ?>
				<div id="branding">
					<img src="<?php echo TIMTHUMB_URL; ?>?src=<?php echo $logo_file_info['url']; ?>&amp;w=300" alt="<?php echo THIS_INSTALL_SET_TITLE; ?>" />
				</div>
			<?php } ?>
		</div>

		<div id="menu">
			<p class="welcome">
				<?php _e('Welcome','pinboxes_template'); ?>, <?php echo html_output($client_info['name']); ?>
			</p>
			<ul>
				<li id="search_box">
					<form action="" name="files_search" method="get">
						<input type="text" name="search" id="search_text" value="<?php echo (isset($_GET['search']) && !empty($_GET['search'])) ? html_output($_GET['search']) : ''; ?>" placeholder="<?php _e('Search...','pinboxes_template'); ?>">
						<button type="submit" id="search_go"><i class="fa fa-search" aria-hidden="true"></i></button>
					</form>
				</li>
				<?php
					if ( !empty( $get_categories['categories'] ) ) {
						$url_client_id	= ( !empty($_GET['client'] ) && CURRENT_USER_LEVEL != '0') ? $_GET['client'] : null;
						$link_template	= BASE_URI . 'my_files/';
				?>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -83,7 +83,7 @@
 		<div id="header">
 			<?php if ($logo_file_info['exists'] === true) { ?>
 				<div id="branding">
-					<img src="<?php echo TIMTHUMB_URL; ?>?src=<?php echo $logo_file_info['url']; ?>&amp;w=300" alt="<?php echo THIS_INSTALL_SET_TITLE; ?>" />
+					<img src="<?php echo TIMTHUMB_URL; ?>?src=<?php echo $logo_file_info['url']; ?>&amp;w=300" alt="<?php echo html_output(THIS_INSTALL_SET_TITLE); ?>" />
 				</div>
 			<?php } ?>
 		</div>
```
