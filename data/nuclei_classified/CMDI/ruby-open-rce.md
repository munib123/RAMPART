# Vulnerability: Ruby Kernel#open/URI.open RCE
**Classification:** CMDI
**Source:** Nuclei Template (`ruby-open-rce.yaml`)

## Description
Ruby's Kernel#open and URI.open enables not only file access but also process invocation by prefixing a pipe symbol (e.g., open(“| ls”)). So, it may lead to Remote Code Execution by using variable input to the argument of Kernel#open and URI.open.

