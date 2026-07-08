# Vulnerability: Thymeleaf - Out of Band Template Injection
**Classification:** THYMELEAF
**Source:** Nuclei Template (`thymeleaf-oob.yaml`)

## Description
Thymeleaf template injection occurs when user input is embedded in a template without proper sanitization. This can lead to remote code execution through Thymeleaf's expression language features.

