# HackerOne Report: type confusion in Sass::ParserState::ParserState(Sass::ParserState const&)
**Report ID:** 66724
**Vulnerability Class:** Memory Corruption - Generic

## Vulnerability Information & PoC
I haven't actually spent much time on the bug, because it doesn't look super exploitable outside of a local DoS, but the attached PoC will crash sassc in the middle of libsass from latest git, trying to deref $0x8, which appears to be the value of some tag in a tagged union.

Let me know if I can help chasing this down, but I mostly wanted to just punt it over the fence.

## Discussion & Remediation Timeline
