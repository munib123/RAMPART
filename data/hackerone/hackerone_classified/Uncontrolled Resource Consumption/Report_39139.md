# HackerOne Report: URL Crashing browser. {Tested on firefox, Chrome and Safari}
**Report ID:** 39139
**Vulnerability Class:** Uncontrolled Resource Consumption

## Vulnerability Information & PoC
Hi again Dear,

I am facing a strange behavior when I try to access this particular URL

 https://hackerone.com/reports/10373 

I test it  on multiple computer with different browser.
Browser goes into indefinite loop and disabled right click ,and after some time it crashes .

It seems like the problem is because of JavaScript .
when I tried to debug it:

It looks like the JS function this  creating problem 

 h.indexOf = function(e, t, n) {
        if (null == e) return -1;
        var r = 0,
            i = e.length;
        if (n) {
            if ("number" != typeof n) return r = h.sortedIndex(e, t), e[r] === t ? r : -1;
            r = 0 > n ? Math.max(0, i + n) : n
        }
        for (; i > r; r++)
            if (e[r] === t) return r;
        return -1
    }


Please have a look and revert if I am wrong.
 

## Discussion & Remediation Timeline
