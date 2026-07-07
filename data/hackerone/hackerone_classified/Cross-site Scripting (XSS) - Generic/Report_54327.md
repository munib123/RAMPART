# HackerOne Report: Persistent cross-site scripting (XSS) in map attribution
**Report ID:** 54327
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hello,

I have found a Persistent Cross Site Scripting vulnerability when using a custom style uploaded by myself.

Mapbox Studio allows create and upload styles for your maps. So if we create a new style with javascript code as attribution value it will be executed when loading a map that uses our evil style. I used the following javascript code for testing:
>"><img src=x onerror=alert(document.cookie)>

To reproduce this vulnerability you must download the Mapbox Studio from [here](https://www.mapbox.com/mapbox-studio/). Then you must write a random name and description. In the Attribution field you must inject the javascript code you want to execute. Save the changes again, upload the project and close the Mapbox Studio.
Now, log into your Mapbox account and go to Styles, select the style you have just created, this will expand the div, and click on "New project". The code will be already executed, but the vulnerability is not as much exploitable as we want.
We want everybody can execute our javascript code so, choose the settings you want in the project we created and save it. Go to your [project list](https://www.mapbox.com/projects/) and search the project we have just saved. If we share this project, everybody who access to it will execute the code we have injected, including people without Mapbox account.

PoC: https://api.tiles.mapbox.com/v4/pr0ph3t.lkag551j/page.html?access_token=pk.eyJ1IjoicHIwcGgzdCIsImEiOiJuRlQ1RDk0In0.qWRU_9DCEAMsAYIEpNTpnw#3/0.00/0.00

Demo video: https://youtu.be/NHjTqjndRik

Regards,
Juan Broullón Sampedro.

## Discussion & Remediation Timeline
