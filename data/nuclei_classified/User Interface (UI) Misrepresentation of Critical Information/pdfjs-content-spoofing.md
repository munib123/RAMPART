# Nuclei Template: Mozilla PDF.js - Content Spoofing
**Template ID:** pdfjs-content-spoofing
**Vulnerability Class:** User Interface (UI) Misrepresentation of Critical Information
**Severity:** Medium
**CWE:** CWE-451
**Source:** Nuclei Template (`mozilla-pdfjs-content-spoofing.yaml`)

## Vulnerability Information & PoC

## Description
Detected PDF.js viewer loads and renders external PDF files without proper origin validation. Versions < v1.3.91 are vulnerable to content spoofing attacks.

## References
- https://groups.google.com/g/mozilla.dev.pdf-js/c/_WdU9T0TRfo
- https://github.com/mozilla/pdf.js/issues/6920
