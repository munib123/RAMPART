# CrossVul Fix Pair: Cross-Site Request Forgery (CSRF) in html
**Pair ID:** 5842_5
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)
**CWE:** CWE-352
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5842_5`)

## Vulnerability Information & PoC

## Description
Cross-Site Request Forgery (CSRF) - When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into...

## Vulnerable Code
```html
Lines 22-62 of the vulnerable file.

                        class="badge badge-important" wicket:id="suffix">[5]</span></a></li>
                  </ul></li>
              </ul></li>
          </ul>
          <wicket:container wicket:id="menuconfig"></wicket:container>
          <div id="pf_sortablecontainer">
            <ul class="nav" role="menu">
              <li id="pf_newentry" class="pf_disable"><input type="text" class="text"><a class="pf_safenewentry"><i
                  class="icon-plus-sign"></i></a></li>
              <li wicket:id="goMobile"><a href="#" wicket:id="link"><wicket:message key="menu.mobileMenu" /></a></li>
              <li wicket:id="menuRepeater"><a href="#" wicket:id="link"><span wicket:id="label">[Generic]</span><span
                  class="badge badge-important" wicket:id="suffix">[5]</span> <b class="caret" wicket:id="caret"></b></a>
                <ul class="dropdown-menu" wicket:id="subMenu">
                  <li wicket:id="subMenuRepeater"><a wicket:id="link"><span wicket:id="label">[Addresses]</span><span
                      class="badge badge-important" wicket:id="suffix">[5]</span></a></li>
                </ul></li>
            </ul>
          </div>
          <form class="navbar-search pull-left" wicket:id="searchForm" autocomplete="off">
            <input type="text" class="search-query span2" placeholder="Search" wicket:id="searchField">
          </form>
          <ul class="nav pull-right">
            <li class="dropdown"><a href="#" class="dropdown-toggle" data-toggle="dropdown"><span wicket:id="user">[Kai Reinhard]</span><b
                class="caret"></b></a>
              <ul class="dropdown-menu">
                <li><a href="wa/layoutSettings" wicket:id="layoutSettingsMenuLink"><wicket:message key="menu.gear.layoutsettings" /></a></li>
                <li><a href="wa/feedback" wicket:id="feedbackLink"><wicket:message key="menu.gear.feedback" /></a></li>
                <li class="divider"></li>
                <li><a href="#" wicket:id="showBookmarkLink"><wicket:message key="menu.gear.showBookmark" /></a></li>
                <li><a wicket:id="documentationLink" href="/myAccount"><wicket:message key="menu.documentation" /></a></li>
                <li><a wicket:id="myAccountLink" href="/myAccount"><wicket:message key="menu.myAccount" /></a></li>
                <li><a wicket:id="logoutLink" href="/login?logout=true"><wicket:message key="menu.logout" /></a></li>
              </ul></li>
          </ul>
        </div>
      </div>
    </div>
  </wicket:panel>

</body>
</html>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,7 @@
           </div>
           <form class="navbar-search pull-left" wicket:id="searchForm" autocomplete="off">
             <input type="text" class="search-query span2" placeholder="Search" wicket:id="searchField">
+            <input type="hidden" wicket:id="csrfToken" />
           </form>
           <ul class="nav pull-right">
             <li class="dropdown"><a href="#" class="dropdown-toggle" data-toggle="dropdown"><span wicket:id="user">[Kai Reinhard]</span><b
```
