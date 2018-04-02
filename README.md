[![Build Status - Master](https://travis-ci.org/juju4/ansible-bro-ids.svg?branch=master)](https://travis-ci.org/juju4/ansible-bro-ids)
[![Build Status - Devel](https://travis-ci.org/juju4/ansible-bro-ids.svg?branch=devel)](https://travis-ci.org/juju4/ansible-bro-ids/branches)

# Bro-ids ansible role

Ansible role to setup Bro IDS
https://www.bro.org

Installation from
* Opensuse repository - 2.5 (rpm or deb)(default)
* SecurityOnion repository (precise or trusty only)
* source - 2.5

## Requirements & Dependencies

### Ansible
It was tested on the following versions:
 * 2.0
 * 2.2

### Ansible Roles
 * juju4.maxmind
 * juju4.ipsumdump
 * juju4.redhat-epel
If you installed the role with ansible-galaxy, these should have been
installed autmatically, otherwise you may need to download them yourself.

### Operating systems

Ubuntu 14.04, 16.04 and Centos7

## Example Playbook

Just include this role in your list.
For example

```
- hosts: server
  roles:
    - juju4.bro-ids

```

?Some nrpe commands are included to help for monitoring.

Post-install check
```
$ sudo /opt/bro/bin/broctl
[BroControl] > install
[BroControl] > diag
```

## Variables

There is a good number of variables to set the different settings.
Some like password should be stored in ansible vault for production systems at least.

```
bro_mode: alone
#bro_mode: manager
#bro_mode: node
#bro_manager: 10.0.0.10
#bro_nodes:
#   - 10.0.0.11
#   - 10.0.0.12
bro_nodes_if: eth0 # TODO: make sure this is used and other ways to set it

## local disk logs limit in days
broids_logexpire_interval: 90

## Only available for Ubuntu 12.04 (EOL Apr 2017), has pfring
use_securityonion_deb: false
## pfring/high network performance = build source
bro_w_pfring: false
## for source install
force_source_build: false
bro_v: 2.4
bro_archive_sha256: 740c0d0b0bec279c2acef5e1b6b4d0016c57cd02a729f5e2924ae4a922e208b2


## mysql setup for passivedns
mysql_user: root
mysql_root_password: mysql_root_pass_to_change_or_get_lost
mysql_old_root_password:
mysql_pdns_user: pdns
mysql_pdns_pass: pdns_pass_to_change_or_get_lost

## MISP setup
broids_misp_url: ''
## it's advised to create a dedicated user with read-only access
broids_misp_apikey: ''

# Add the full path to intel files (besides those from MISP), as outlined in
# http://blog.bro.org/2014/01/intelligence-data-and-bro_4980.html , to the
# broids_intels array:
broids_intels: []

## install critical stack (need to register to get API key, https://intel.criticalstack.com/)
bro_cs_enable: false
bro_cs_apikey: ''
bro_cs_proxy: ''
#bro_cs_proxy: 'http://username:password@hostname:port'
bro_cs_autorestart: false

broids_vt_api_key: ''
```

## Supporting software / integrations
Besides the software that will be installed by the included roles (maxmind, 
ipsumdump), the following packages will be installed in addition to Bro:
 * [bro-pdns](https://github.com/JustinAzoff/bro-pdns) (Passive DNS)
 * mysql (to store Passive DNS data)
   * See mysql setup for passivedns above to configure these correctly
 * [MISP2Bro](https://github.com/thnyheim/misp2bro.git) (Convert MISP IOCs to 
   Bro Intel): See above to configure this
 * A number of popular Bro scripts (see tasks/bro-scripts.yml for details)
 * [JA3 Integration](https://www.splunk.com/blog/2017/12/18/configuring-ja3-with-bro-for-splunk.html)
 * [Critical Stack Intel](https://intel.criticalstack.com/): See above to 
   configure this
 * [VirusTotal](https://www.virustotal.com/en/documentation/public-api/): See
   above to configure this

## Continuous integration

This role has a travis basic test (for github), more advanced with kitchen and also a Vagrantfile (test/vagrant).

Once you ensured all necessary roles are present, You can test with:
```
$ cd /path/to/roles/mig
$ kitchen verify
$ kitchen login
```
or
```
$ cd /path/to/roles/mig/test/vagrant
$ vagrant up
$ vagrant ssh
```

## Troubleshooting & Known issues

* At May 2016, kitchen tests are validated. Travis still have issues (Read-only filesystem. Huh?) and some ansible variable (ansible_default_ipv4) not set
* role is not idempotent, mostly broctl
* "Error bro: capstats failed (Host 127.0.0.1 is not alive)" (/opt/bro/logs/stats/stats.log)
* Monit: bro_rc and bro process falls in "Not monitored" state so no automatic restart

## License

BSD 2-clause



