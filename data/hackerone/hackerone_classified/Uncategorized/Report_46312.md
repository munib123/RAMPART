# HackerOne Report: In markdown, parsing things like @danlec and #46072 after links is unsafe
**Report ID:** 46312
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
(Let me preface this by saying that I haven't worked out an actual exploit for this, and there may not be one, but when #46072 is disclosed, folks will probably be taking a closer look at HackerOne's markdown parsing and may find a way to turn this bug into something)

It looks like the links for things like @danlec and #46072 are being added to the HTML after the initial markdown is processed; this leads to situations where links end up malformed because link markup is being added in an unexpected place (inside the attribute values of existing links)

For example:

```
[text](http://danlec.com " @danlec ")
```

renders as

[text](http://danlec.com " @danlec ")

i.e.

```
<p><a title=" <a href=" danlec"="">@danlec</a> " href="http://danlec.com"&gt;text</p>
```

As you can see, there's an unexpected `danlec"` attribute on the link tag.

The same kind of issue exists for references to other submissions, e.g.

```
[text](http://danlec.com " #46072 ")
```

renders as 

[text](http://danlec.com " #46072 ")

```
<p><a title=" <a href=" reports="" 46072"="">#46072</a> " href="http://danlec.com"&gt;text</p>
```

… with an  unexpected `reports` and `46072"` attribute


## Discussion & Remediation Timeline
