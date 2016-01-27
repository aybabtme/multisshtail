# multisshtail

Tails a set of files over a set of hosts, over SSH.

## Usage

Caveat: if you use this, your log stack has problems. You should have all your logs sent to a centralized logging system. Don't use this tool as your day to day log monitoring tool.

``` bash
$ multisshtail -addrs "host1:22,host2:22,host3:22" -files "/var/log/production.log,/var/log/errors.log"
# prints log lines
```
