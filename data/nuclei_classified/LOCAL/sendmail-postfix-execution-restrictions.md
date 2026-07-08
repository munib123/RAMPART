# Vulnerability: Sendmail/Postfix Execution Restrictions Misconfigured
**Classification:** LOCAL
**Source:** Nuclei Template (`sendmail-postfix-execution-restrictions.yaml`)

## Description
General users were not restricted from executing Sendmail with the q option, and the Postfix binary lacked proper permission controls.This misconfiguration allowed unauthorized users to manipulate the mail queue or disrupt mail delivery.

