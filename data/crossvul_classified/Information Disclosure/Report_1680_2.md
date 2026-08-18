# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 1680_2
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1680_2`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 326-356 of the vulnerable file.

            if ($existing->count) {
                return true;
            }
        }
    }

    return false;
}

function rcmail_message_contactphoto($attrib)
{
    global $RCMAIL, $MESSAGE;

    $placeholder = $attrib['placeholder'] ? $RCMAIL->config->get('skin_path') . $attrib['placeholder'] : null;

    if ($MESSAGE->sender) {
        $photo_img = $RCMAIL->url(array(
            '_task'   => 'addressbook',
            '_action' => 'photo',
            '_email'  => $MESSAGE->sender['mailto'],
            '_alt'    => $placeholder,
        ));

        $attrib['onerror'] = "this.src = '" . ($placeholder ? $placeholder : 'program/resources/blank.gif') . "'";
    }
    else {
        $photo_img = $placeholder ? $placeholder : 'program/resources/blank.gif';
    }

    return html::img(array('src' => $photo_img) + $attrib);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -343,7 +343,6 @@
             '_task'   => 'addressbook',
             '_action' => 'photo',
             '_email'  => $MESSAGE->sender['mailto'],
-            '_alt'    => $placeholder,
         ));
 
         $attrib['onerror'] = "this.src = '" . ($placeholder ? $placeholder : 'program/resources/blank.gif') . "'";
```
