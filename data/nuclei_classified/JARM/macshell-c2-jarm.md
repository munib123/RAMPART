# Vulnerability: Macshell C2 JARM - Detect
**Classification:** JARM
**Source:** Nuclei Template (`macshell-c2-jarm.yaml`)

## Description
MacShellSwift is a proof of concept MacOS post-exploitation tool written in Swift using encrypted sockets. This tool has been tested both pre and post-Catalina. I rewrote a prior tool of mine MacShell (one of my repos) and changed the client to Swift instead of python. This tool consists of two parts: a server script and a client binary. I wrote this tool to help blue teamers proactively guage detections against macOS post-exploitation methods that use macOS internal calls. Red teams can also find this of use for getting ideas around using Swift for macOS post-exploitation

