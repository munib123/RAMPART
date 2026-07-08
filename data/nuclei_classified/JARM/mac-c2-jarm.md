# Vulnerability: MacC2 JARM - Detect
**Classification:** JARM
**Source:** Nuclei Template (`mac-c2-jarm.yaml`)

## Description
MacC2 is a macOS post exploitation tool written in python that uses Objective C calls or python libraries as opposed to command line executions. The client is written in python2, which though deprecated is still being shipped with base Big Sur installs. It is possible down the road that Apple will remove python2 (or python altogether) from base macOS installs but as of Nov 2020 this is not the case. Apple plans to eventually remove scripting runtimes from base macOS installs, but it is unknown when that will happen since Big Sur includes python.

