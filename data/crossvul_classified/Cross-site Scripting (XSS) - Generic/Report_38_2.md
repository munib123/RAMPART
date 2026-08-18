# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 38_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `38_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 437-477 of the vulnerable file.

</code></pre><p>Since getting the ID of a note is not straightforward, each app provides a way to create such link. In the <strong>desktop app</strong>, right click on a note an select &quot;Copy Markdown link&quot;. In the <strong>mobile app</strong>, open a note and, in the top right menu, select &quot;Copy Markdown link&quot;. You can then paste this link anywhere in another note.</p>
<h2 id="math-notation">Math notation</h2>
<p>Math expressions can be added using the <a href="https://khan.github.io/KaTeX/">Katex notation</a>. To add an inline equation, wrap the expression in <code>$EXPRESSION$</code>, eg. <code>$\sqrt{3x-1}+(1+x)^2$</code>. To create an expression block, wrap it as follow:</p>
<pre><code>$$
EXPRESSION
$$
</code></pre><p>For example:</p>
<pre><code>$$
f(x) = \int_{-\infty}^\infty
    \hat f(\xi)\,e^{2 \pi i \xi x}
    \,d\xi
$$
</code></pre><p>Here is an example with the Markdown and rendered result side by side:</p>
<p><img src="https://joplin.cozic.net/images/Katex.png" style="max-width: 100%; max-height: 35em;"></p>
<h2 id="checkboxes">Checkboxes</h2>
<p>Checkboxes can be added like so:</p>
<pre><code>- [ ] Milk
- [ ] Rice
- [ ] Eggs
</code></pre><p>The checkboxes can then be ticked in the mobile and desktop applications.</p>
<h1 id="donations">Donations</h1>
<p>Donations to Joplin support the development of the project. Developing quality applications mostly takes time, but there are also some expenses, such as digital certificates to sign the applications, app store fees, hosting, etc. Most of all, your donation will make it possible to keep up the current development standard.</p>
<p>Please see the <a href="https://joplin.cozic.net/donate/">donation page</a> for information on how to support the development of Joplin.</p>
<h1 id="community">Community</h1>
<ul>
<li>For general discussion about Joplin, user support, software development questions, and to discuss new features, go to the <a href="https://discourse.joplin.cozic.net/">Joplin Forum</a>. It is possible to login with your GitHub account.</li>
<li>For bug reports and feature requests, go to the <a href="https://github.com/laurent22/joplin/issues">GitHub Issue Tracker</a>.</li>
<li>The latest news are often posted <a href="https://twitter.com/laurent2233">on this Twitter account</a>.</li>
</ul>
<h1 id="contributing">Contributing</h1>
<p>Please see the guide for information on how to contribute to the development of Joplin: <a href="https://github.com/laurent22/joplin/blob/master/CONTRIBUTING.md">https://github.com/laurent22/joplin/blob/master/CONTRIBUTING.md</a></p>
<h1 id="localisation">Localisation</h1>
<p>Joplin is currently available in the languages below. If you would like to contribute a <strong>new translation</strong>, it is quite straightforward, please follow these steps:</p>
<ul>
<li><a href="https://poedit.net/">Download Poedit</a>, the translation editor, and install it.</li>
<li><a href="https://raw.githubusercontent.com/laurent22/joplin/master/CliClient/locales/joplin.pot">Download the file to be translated</a>.</li>
<li>In Poedit, open this .pot file, go into the Catalog menu and click Configuration. Change &quot;Country&quot; and &quot;Language&quot; to your own country and language.</li>
<li>From then you can translate the file. Once it is done, please either <a href="https://github.com/laurent22/joplin/pulls">open a pull request</a> or send the file to <a href="https://raw.githubusercontent.com/laurent22/joplin/master/Assets/Adresse.png">this address</a>.</li>
</ul>
<p>This translation will apply to the three applications - desktop, mobile and terminal.</p>
<p>To <strong>update a translation</strong>, follow the same steps as above but instead of getting the .pot file, get the .po file for your language from the table below.</p>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -454,6 +454,8 @@
 - [ ] Rice
 - [ ] Eggs
 </code></pre><p>The checkboxes can then be ticked in the mobile and desktop applications.</p>
+<h2 id="html-support">HTML support</h2>
+<p>Only the <code>&lt;br&gt;</code> tag is supported - it can be used to force a new line, which is convenient to insert new lines inside table cells. For security reasons, other HTML tags are not supported.</p>
 <h1 id="donations">Donations</h1>
 <p>Donations to Joplin support the development of the project. Developing quality applications mostly takes time, but there are also some expenses, such as digital certificates to sign the applications, app store fees, hosting, etc. Most of all, your donation will make it possible to keep up the current development standard.</p>
 <p>Please see the <a href="https://joplin.cozic.net/donate/">donation page</a> for information on how to support the development of Joplin.</p>
@@ -499,14 +501,14 @@
 <td><img src="https://joplin.cozic.net/images/flags/country-4x3/hr.png" alt=""></td>
 <td>Croatian</td>
 <td><a href="https://github.com/laurent22/joplin/blob/master/CliClient/locales/hr_HR.po">hr_HR</a></td>
-<td>Hrvoje Mandić <a href="&#109;&#x61;&#x69;&#x6c;&#x74;&#x6f;&#x3a;&#116;&#x72;&#98;&#117;&#104;&#x6f;&#109;&#64;&#110;&#x65;&#116;&#x2e;&#104;&#114;">&#116;&#x72;&#98;&#117;&#104;&#x6f;&#109;&#64;&#110;&#x65;&#116;&#x2e;&#104;&#114;</a></td>
+<td>Hrvoje Mandić <a href="&#109;&#x61;&#105;&#x6c;&#116;&#x6f;&#x3a;&#116;&#x72;&#x62;&#x75;&#x68;&#111;&#x6d;&#x40;&#x6e;&#x65;&#116;&#46;&#x68;&#x72;">&#116;&#x72;&#x62;&#x75;&#x68;&#111;&#x6d;&#x40;&#x6e;&#x65;&#116;&#46;&#x68;&#x72;</a></td>
 <td>61%</td>
 </tr>
 <tr>
 <td><img src="https://joplin.cozic.net/images/flags/country-4x3/cz.png" alt=""></td>
 <td>Czech</td>
 <td><a href="https://github.com/laurent22/joplin/blob/master/CliClient/locales/cs_CZ.po">cs_CZ</a></td>
-<td>Lukas Helebrandt <a href="&#109;&#x61;&#x69;&#x6c;&#x74;&#x6f;&#x3a;&#108;&#x75;&#x6b;&#97;&#x73;&#x40;&#x61;&#x69;&#121;&#97;&#46;&#x63;&#x7a;">&#108;&#x75;&#x6b;&#97;&#x73;&#x40;&#x61;&#x69;&#121;&#97;&#46;&#x63;&#x7a;</a></td>
+<td>Lukas Helebrandt <a href="&#x6d;&#x61;&#105;&#108;&#116;&#x6f;&#x3a;&#108;&#117;&#x6b;&#x61;&#115;&#64;&#97;&#x69;&#121;&#97;&#46;&#99;&#122;">&#108;&#117;&#x6b;&#x61;&#115;&#64;&#97;&#x69;&#121;&#97;&#46;&#99;&#122;</a></td>
 <td>95%</td>
 </tr>
 <tr>
@@ -520,7 +522,7 @@
 <td><img src="https://joplin.cozic.net/images/flags/country-4x3/de.png" alt=""></td>
 <td>Deutsch</td>
 <td><a href="https://github.com/laurent22/joplin/blob/master/CliClient/locales/de_DE.po">de_DE</a></td>
-<td>Philipp Zumstein <a href="&#x6d;&#97;&#x69;&#108;&#x74;&#x6f;&#x3a;&#122;&#x75;&#x70;&#104;&#105;&#108;&#105;&#x70;&#64;&#103;&#109;&#97;&#x69;&#x6c;&#46;&#x63;&#111;&#x6d;">&#122;&#x75;&#x70;&#104;&#105;&#108;&#105;&#x70;&#64;&#103;&#109;&#97;&#x69;&#x6c;&#46;&#x63;&#111;&#x6d;</a></td>
+<td>Philipp Zumstein <a href="&#x6d;&#x61;&#105;&#108;&#x74;&#x6f;&#58;&#122;&#117;&#x70;&#104;&#x69;&#108;&#x69;&#x70;&#64;&#x67;&#109;&#x61;&#x69;&#x6c;&#x2e;&#x63;&#x6f;&#x6d;">&#122;&#117;&#x70;&#104;&#x69;&#108;&#x69;&#x70;&#64;&#x67;&#109;&#x61;&#x69;&#x6c;&#x2e;&#x63;&#x6f;&#x6d;</a></td>
 <td>98%</td>
 </tr>
 <tr>
@@ -534,7 +536,7 @@
 <td><img src="https://joplin.cozic.net/images/flags/country-4x3/es.png" alt=""></td>
 <td>Español</td>
 <td><a href="https://github.com/laurent22/joplin/blob/master/CliClient/locales/es_ES.po">es_ES</a></td>
-<td>Fernando Martín <a href="&#x6d;&#x61;&#x69;&#x6c;&#x74;&#x6f;&#x3a;&#102;&#64;&#x6d;&#114;&#116;&#x6e;&#x2e;&#101;&#115;">&#102;&#64;&#x6d;&#114;&#116;&#x6e;&#x2e;&#101;&#115;</a></td>
+<td>Fernando Martín <a href="&#x6d;&#97;&#105;&#x6c;&#116;&#111;&#58;&#102;&#64;&#109;&#x72;&#116;&#110;&#46;&#x65;&#x73;">&#102;&#64;&#109;&#x72;&#116;&#110;&#46;&#x65;&#x73;</a></td>
 <td>99%</td>
 </tr>
 <tr>
@@ -548,7 +550,7 @@
 <td><img src="https://joplin.cozic.net/images/flags/country-4x3/es.png" alt=""></td>
 <td>Galician</td>
 <td><a href="https://github.com/laurent22/joplin/blob/master/CliClient/locales/gl_ES.po">gl_ES</a></td>
-<td>Marcos Lans <a href="&#x6d;&#97;&#x69;&#108;&#116;&#111;&#58;&#x6d;&#97;&#114;&#99;&#111;&#x73;&#108;&#x61;&#110;&#x73;&#103;&#97;&#x72;&#122;&#97;&#64;&#x67;&#x6d;&#x61;&#x69;&#108;&#46;&#x63;&#111;&#109;">&#x6d;&#97;&#114;&#99;&#111;&#x73;&#108;&#x61;&#110;&#x73;&#103;&#97;&#x72;&#122;&#97;&#64;&#x67;&#x6d;&#x61;&#x69;&#108;&#46;&#x63;&#111;&#109;</a></td>
+<td>Marcos Lans <a href="&#x6d;&#x61;&#x69;&#x6c;&#116;&#111;&#x3a;&#109;&#x61;&#114;&#x63;&#x6f;&#115;&#x6c;&#97;&#110;&#115;&#103;&#97;&#x72;&#122;&#x61;&#x40;&#103;&#109;&#97;&#105;&#x6c;&#46;&#x63;&#x6f;&#x6d;">&#109;&#x61;&#114;&#x63;&#x6f;&#115;&#x6c;&#97;&#110;&#115;&#103;&#97;&#x72;&#122;&#x61;&#x40;&#103;&#109;&#97;&#105;&#x6c;&#46;&#x63;&#x6f;&#x6d;</a></td>
 <td>95%</td>
 </tr>
 <tr>
@@ -569,14 +571,14 @@
 <td><img src="https://joplin.cozic.net/images/flags/country-4x3/br.png" alt=""></td>
 <td>Português (Brasil)</td>
 <td><a href="https://github.com/laurent22/joplin/blob/master/CliClient/locales/pt_BR.po">pt_BR</a></td>
-<td>Renato Nunes Bastos <a href="&#x6d;&#x61;&#105;&#108;&#116;&#111;&#58;&#x72;&#x6e;&#x62;&#97;&#x73;&#116;&#x6f;&#x73;&#x40;&#x67;&#109;&#97;&#x69;&#108;&#46;&#x63;&#x6f;&#109;">&#x72;&#x6e;&#x62;&#97;&#x73;&#116;&#x6f;&#x73;&#x40;&#x67;&#109;&#97;&#x69;&#108;&#46;&#x63;&#x6f;&#109;</a></td>
+<td>Renato Nunes Bastos <a href="&#x6d;&#97;&#105;&#108;&#x74;&#111;&#x3a;&#x72;&#110;&#x62;&#x61;&#115;&#x74;&#111;&#x73;&#x40;&#x67;&#109;&#x61;&#105;&#108;&#46;&#99;&#111;&#109;">&#x72;&#110;&#x62;&#x61;&#115;&#x74;&#111;&#x73;&#x40;&#x67;&#109;&#x61;&#105;&#108;&#46;&#99;&#111;&#109;</a></td>
 <td>97%</td>
 </tr>
 <tr>
 <td><img src="https://joplin.cozic.net/images/flags/country-4x3/ru.png" alt=""></td>
 <td>Русский</td>
 <td><a href="https://github.com/laurent22/joplin/blob/master/CliClient/locales/ru_RU.po">ru_RU</a></td>
-<td>Artyom Karlov <a href="&#x6d;&#x61;&#x69;&#x6c;&#x74;&#111;&#x3a;&#97;&#114;&#116;&#x79;&#x6f;&#x6d;&#x2e;&#x6b;&#97;&#x72;&#x6c;&#x6f;&#x76;&#64;&#x67;&#x6d;&#97;&#105;&#x6c;&#x2e;&#x63;&#111;&#109;">&#97;&#114;&#116;&#x79;&#x6f;&#x6d;&#x2e;&#x6b;&#97;&#x72;&#x6c;&#x6f;&#x76;&#64;&#x67;&#x6d;&#97;&#105;&#x6c;&#x2e;&#x63;&#111;&#109;</a></td>
+<td>Artyom Karlov <a href="&#x6d;&#97;&#x69;&#108;&#x74;&#x6f;&#x3a;&#97;&#x72;&#116;&#121;&#111;&#109;&#x2e;&#107;&#97;&#114;&#x6c;&#x6f;&#x76;&#x40;&#x67;&#109;&#97;&#x69;&#108;&#x2e;&#x63;&#x6f;&#109;">&#97;&#x72;&#116;&#121;&#111;&#109;&#x2e;&#107;&#97;&#114;&#x6c;&#x6f;&#x76;&#x40;&#x67;&#109;&#97;&#x69;&#108;&#x2e;&#x63;&#x6f;&#109;</a></td>
 <td>94%</td>
 </tr>
 <tr>
```
