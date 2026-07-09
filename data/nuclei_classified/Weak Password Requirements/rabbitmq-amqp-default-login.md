# Nuclei Template: RabbitMQ AMQP - Default Login
**Template ID:** rabbitmq-amqp-default-login
**Vulnerability Class:** Weak Password Requirements
**Severity:** High
**CWE:** CWE-521
**Source:** Nuclei Template (`rabbitmq-amqp-default-login.yaml`)

## Vulnerability Information & PoC

## Description
RabbitMQ server accepts connections with weak or default credentials over the AMQP 0-9-1 protocol (port 5672).Default credentials (guest/guest) or commonly used weak passwords were found, allowing unauthorized access to the message broker, its queues, exchanges, and all data flowing through them.

## Impact
An attacker with valid AMQP credentials can connect to the broker, consume or publish messages,create/delete queues and exchanges, and potentially access sensitive application data.

## Remediation
Change default credentials immediately. Enforce strong password policies. Restrict the guest account to localhost connections only (RabbitMQ default behavior). Enable TLS for AMQP connections. Use vhosts for access isolation.

## References
- https://www.rabbitmq.com/docs/access-control
- https://www.rabbitmq.com/docs/passwords
- https://www.rabbitmq.com/docs/amqp-0-9-1-reference
