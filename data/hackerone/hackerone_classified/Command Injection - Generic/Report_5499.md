# HackerOne Report: Arbitrary command execution in MS-DOS
**Report ID:** 5499
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
Versions 1.1 and 2.0 of MS-DOS allow a malicious actor to execute arbitrary system commands via the main application interface.

Prerequisites:
* MS-DOS 1.1 or MS-DOS 2.0 installation
* Input device (e.g. keyboard)

Steps to reproduce:
* Enter the _command mode_
* Type `VER` to make sure that the system is on of the affected versions
* Pass a known system command like `HELP` to see that the system responds correctly
* Use `EXEC PROGRAM_NAME.BAT` to execute arbitrary programs

See PoC below.

## Discussion & Remediation Timeline
