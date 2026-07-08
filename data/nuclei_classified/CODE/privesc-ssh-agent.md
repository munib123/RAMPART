# Vulnerability: ssh-agent - Privilege Escalation
**Classification:** CODE
**Source:** Nuclei Template (`privesc-ssh-agent.yaml`)

## Description
ssh-agent is a program that helps manage and store private keys used for SSH authentication. It is often used to hold the decrypted private keys in memory, allowing for seamless authentication to remote servers without the need to re-enter passphrases for the keys.

