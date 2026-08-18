# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 3940_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3940_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 550-590 of the vulnerable file.

            'iso_8859_2' => 'ISO-8859-2 (Latin-2, Central European)',
            'iso_8859_3' => 'ISO-8859-3 (Latin-3, South European)',
            'iso_8859_4' => 'ISO-8859-4 (Latin-4, North European)',
            'iso_8859_5' => 'ISO-8859-5 (Latin, Cyrillic)',
            'iso_8859_6' => 'ISO-8859-6 (Latin, Arabic)',
            'iso_8859_7' => 'ISO-8859-7 (Latin, Greek)',
            'iso_8859_8' => 'ISO-8859-8 (Latin, Hebrew)',
            'iso_8859_0' => 'ISO-8859-9 (Latin-5, Turkish)',
            'iso_8859_10' => 'ISO-8859-10 (Latin-6, Nordic)',
            'iso_8859_11' => 'ISO-8859-11 (Latin, Thai)',
            'iso_8859_13' => 'ISO-8859-13 (Latin-7, Baltic Rim)',
            'iso_8859_14' => 'ISO-8859-14 (Latin-8, Celtic)',
            'iso_8859_15' => 'ISO-8859-15 (Latin-9, Western European revision with euro sign)',
            'windows_1250' => 'Windows-1250 (CP1250, Central and Eastern European)',
            'windows_1251' => 'Windows-1251 (CP1251)',
            'windows_1252' => 'Windows-1252 (CP1252)',
        ],
    ],
    'permissions' => [
        'manage_media' => 'Upload and manage media contents - images, videos, sounds, documents',
    ],
    'mediafinder' => [
        'label' => 'Media Finder',
        'default_prompt' => 'Click the %s button to find a media item',
        'no_image' => 'The image could not be found',
    ],
    'media' => [
        'menu_label' => 'Media',
        'upload' => 'Upload',
        'move' => 'Move',
        'delete' => 'Delete',
        'add_folder' => 'Add folder',
        'search' => 'Search',
        'display' => 'Display',
        'filter_everything' => 'Everything',
        'filter_images' => 'Images',
        'filter_video' => 'Video',
        'filter_audio' => 'Audio',
        'filter_documents' => 'Documents',
        'library' => 'Library',
        'size' => 'Size',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -567,6 +567,7 @@
     ],
     'permissions' => [
         'manage_media' => 'Upload and manage media contents - images, videos, sounds, documents',
+        'allow_unsafe_markdown' => 'Use unsafe Markdown (can use HTML & JS)',
     ],
     'mediafinder' => [
         'label' => 'Media Finder',
```
