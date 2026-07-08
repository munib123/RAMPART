# Vulnerability: Java Debug Wire Protocol - Detect
**Classification:** NETWORK
**Source:** Nuclei Template (`jdwp-detect.yaml`)

## Description
JDWP, short for Java Debug Wire Protocol, is a standard feature in the Java platform, designed to help developers debug live applications. It allows remote inspection of threads, memory, and execution flow without restarting the application. To enable it, developers typically start the JVM with a flag like the one below. This setup tells the JVM to listen for debugger connections on port 5005 and accept incoming connections on all interfaces.

