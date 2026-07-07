# HackerOne Report: XSS on [/concrete/concrete/elements/dashboard/sitemap.php]
**Report ID:** 6853
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Alright, here's the other bug I said I would report. I have found the file that is affected by this bug, which is outlined in the title. The affected file is here - /concrete/concrete/elements/dashboard/sitemap.php

On line 40, this section:

<div id="tree" sitemap-wrapper="1" sitemap-select-callback="<?php echo $callback?>"

PHP echoes the $callback without filtering any user input. Here is the PoC link - 

http://localhost/concrete/index.php/tools/required/pages/search_dialog?sitemap_select_mode=%22%3E%3Cscript%3Ealert%280%29%3C/script%3E

Change localhost/ to wherever you're hosting your concrete installation.

That might not be the source of the problem, but I used grep to find the place where it was echoed.

Thank you.



## Discussion & Remediation Timeline
