# Vulnerability: Erlang Port Mapper Daemon
**Classification:** DEMON
**Source:** Nuclei Template (`erlang-daemon.yaml`)

## Description
The erlang port mapper daemon is used to coordinate distributed erlang instances. His job is to keep track of which node name listens on which address. Hence, epmd map symbolic node names to machine addresses.

