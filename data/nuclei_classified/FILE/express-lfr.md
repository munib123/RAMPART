# Vulnerability: Express - Local File Read
**Classification:** FILE
**Source:** Nuclei Template (`express-lfr.yaml`)

## Description
Untrusted user input in express render() function can result in arbitrary file read if hbs templating is used.

