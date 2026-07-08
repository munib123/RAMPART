# Vulnerability: Mozilla PDF.js - Content Spoofing
**Classification:** CWE-451
**Source:** Nuclei Template (`mozilla-pdfjs-content-spoofing.yaml`)

## Description
Detected PDF.js viewer loads and renders external PDF files without proper origin validation. Versions < v1.3.91 are vulnerable to content spoofing attacks.

