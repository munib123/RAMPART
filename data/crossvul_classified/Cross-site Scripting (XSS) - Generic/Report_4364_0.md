# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 4364_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4364_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 55-95 of the vulnerable file.

{% block javascripts %}
<script src="https://cdn.jsdelivr.net/npm/fuse.js@6.0.4"></script>
<script>
    // Since the serer loading could take who knows how long, we'll load in JS so it says "Loading..."" in the page
    $(document).ready(function () {
        var xhr = new XMLHttpRequest();
        var url = "{{ url_for('home_blueprint.getservers') }}"
        xhr.open("GET", url, true)
        xhr.setRequestHeader("Content-Type", "application/json")
        xhr.onreadystatechange = function () {
            if (xhr.readyState !== 4) { return }
            var json = JSON.parse(xhr.responseText)
            if (json.status === 0) {
                $("#serverrow").html(`<div class="col-md-12"><h1>${json["message"]}</h1></div>`)
            } else {
                if (json.data.length === 0) {
                    $("#serverrow").html(`<div class="col-md-12"><h1>{{ _("You're not in any servers with elevated permissions!") }}</h1></div>`)
                } else {
                    var base_guild_url = "{{ url_for('home_blueprint.guild', guild='123456789123456789') }}"
                    $("#serverrow").html("")
                    for (let g of json.data) {
                        var current_guild_url = base_guild_url.replace("123456789123456789", g.id)
                        $("#serverrow").append(`
                            <div class="col-xl-2 col-lg-3 col-md-4 col-sm-6 col-12 guildcard" style="margin-bottom: 50px">
                                <a href="${current_guild_url}">
                                    <div class="card h-100" onmouseover="playGif(this)" onmouseout="stopGif(this)">
                                        <img class="card-img-top" src="${g.icon}png" alt="Card image cap" data-src-url="${g.icon}" data-is-animated=${g.animated}>
                                        <div class="card-body">
                                            <h5 class="card-title">${g.name}</h5>
                                            <p class="card-text">Owner: ${g.owner}</p>
                                        </div>
                                    </div>
                                </a>
                            </div>
                        `)
                    }
                }
            }
        }
        try {
            xhr.send()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,6 +72,7 @@
                 } else {
                     var base_guild_url = "{{ url_for('home_blueprint.guild', guild='123456789123456789') }}"
                     $("#serverrow").html("")
+                    let counter = 0
                     for (let g of json.data) {
                         var current_guild_url = base_guild_url.replace("123456789123456789", g.id)
                         $("#serverrow").append(`
@@ -80,13 +81,16 @@
                                     <div class="card h-100" onmouseover="playGif(this)" onmouseout="stopGif(this)">
                                         <img class="card-img-top" src="${g.icon}png" alt="Card image cap" data-src-url="${g.icon}" data-is-animated=${g.animated}>
                                         <div class="card-body">
-                                            <h5 class="card-title">${g.name}</h5>
-                                            <p class="card-text">Owner: ${g.owner}</p>
+                                            <h5 class="card-title" id="guild-counter-${counter}">Loading...</h5>
+                                            <p class="card-text" id="owner-counter-${counter}">Owner: Loading...</p>
                                         </div>
                                     </div>
                                 </a>
                             </div>
                         `)
+                        $(`#guild-counter-${counter}`).text(g.name)
+                        $(`#owner-counter-${counter}`).text(g.owner)
+                        counter += 1
                     }
                 }
             }
```
