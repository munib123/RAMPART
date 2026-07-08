# Vulnerability: RabbitMQ AMQP - Default Login
**Classification:** CWE-521
**Source:** Nuclei Template (`rabbitmq-amqp-default-login.yaml`)

## Description
RabbitMQ server accepts connections with weak or default credentials over the AMQP 0-9-1 protocol (port 5672).Default credentials (guest/guest) or commonly used weak passwords were found, allowing unauthorized access to the message broker, its queues, exchanges, and all data flowing through them.

## Secure Mitigation
Change default credentials immediately. Enforce strong password policies. Restrict the guest account to localhost connections only (RabbitMQ default behavior). Enable TLS for AMQP connections. Use vhosts for access isolation.

