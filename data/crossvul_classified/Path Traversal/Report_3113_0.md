# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 3113_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3113_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 212-252 of the vulnerable file.

				options: {
					banner: '/* This includes 2 files: jquery.textcomplete.js, textcomplete.init.js */\n'
				},
				nonull: true, // Display missing files
				src: ['rsc/js/jquery/jquery.textcomplete.js', 'rsc/js/textcomplete.init.js'],
				dest: 'rsc/js/build/textcomplete.bmin.js'
			},
			// JS files that are used on front-office standard skins:
			evo_frontoffice: {
				options: {
					banner: '/* This includes 8 files: src/evo_modal_window.js, src/evo_images.js, src/evo_user_crop.js, src/evo_user_report.js, src/evo_user_contact_groups.js, src/evo_rest_api.js, src/evo_item_flag.js, ajax.js */\n'
				},
				nonull: true, // Display missing files
				src: ['rsc/js/src/evo_modal_window.js',
							'rsc/js/src/evo_images.js',
							'rsc/js/src/evo_user_crop.js',
							'rsc/js/src/evo_user_report.js',
							'rsc/js/src/evo_user_contact_groups.js',
							'rsc/js/src/evo_rest_api.js',
							'rsc/js/src/evo_item_flag.js',
							'rsc/js/ajax.js'],
				dest: 'rsc/js/build/evo_frontoffice.bmin.js'
			},
			// JS files that are used on front-office bootstrap skins:
			evo_frontoffice_bootstrap: {
				options: {
					banner: '/* This includes 8 files: src/bootstrap-evo_modal_window.js, src/evo_images.js, src/evo_user_crop.js, src/evo_user_report.js, src/evo_user_contact_groups.js, src/evo_rest_api.js, src/evo_item_flag.js, ajax.js */\n'
				},
				nonull: true, // Display missing files
				src: ['rsc/js/src/bootstrap-evo_modal_window.js',
							'rsc/js/src/evo_images.js',
							'rsc/js/src/evo_user_crop.js',
							'rsc/js/src/evo_user_report.js',
							'rsc/js/src/evo_user_contact_groups.js',
							'rsc/js/src/evo_rest_api.js',
							'rsc/js/src/evo_item_flag.js',
							'rsc/js/ajax.js'],
				dest: 'rsc/js/build/bootstrap-evo_frontoffice.bmin.js'
			},
			// JS files that are used on back-office standard skins:
			evo_backoffice: {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -229,6 +229,7 @@
 							'rsc/js/src/evo_user_contact_groups.js',
 							'rsc/js/src/evo_rest_api.js',
 							'rsc/js/src/evo_item_flag.js',
+							'rsc/js/src/evo_links.js',
 							'rsc/js/ajax.js'],
 				dest: 'rsc/js/build/evo_frontoffice.bmin.js'
 			},
@@ -245,6 +246,7 @@
 							'rsc/js/src/evo_user_contact_groups.js',
 							'rsc/js/src/evo_rest_api.js',
 							'rsc/js/src/evo_item_flag.js',
+							'rsc/js/src/evo_links.js',
 							'rsc/js/ajax.js'],
 				dest: 'rsc/js/build/bootstrap-evo_frontoffice.bmin.js'
 			},
```
