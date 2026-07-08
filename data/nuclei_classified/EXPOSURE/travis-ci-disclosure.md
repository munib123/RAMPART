# Vulnerability: Travis CI Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`travis-ci-disclosure.yaml`)

## Description
Travis CI is a Software as a Service (SaaS) based continuous integration service used to build and test software projects. By defining a configuration file named `.travis.yml` in their source code repositories, developers can customize their applications build workflows.

## Secure Mitigation
Ensure that the `.travis.yml` file is not deployed with the application or, at least, is not exposed in a web server directory by setting proper permissions on it. If sensitive information like credentials are leaked in the exposed file, they should be revoked and reset on the affected assets.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.travis.yml
GET {{BaseURL}}/matomo/.travis.yml
GET {{BaseURL}}/ckeditor/.travis.yml
```

