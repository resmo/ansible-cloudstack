Ansible Cloudstack Module
=========================

Manages instances on Apache CloudStack, Citrix CloudPlatform and Exoscale.

Requirements
------------
Uses Exosclale's python cs library. Visit https://github.com/exoscale/cs for more infos about storing credentials locally.


Examples
--------

```
# Create a virtual machine on CloudStack
- local_action:
    module: cs_vm
    name: web-vm-1
    template: 'Linux Debian 7 64-bit'
    ssh_key: 'john@example.com'
    api_key: '...'
    secret_key: '...'
    url: https://cloud.example.com/client/api


# Create a virtual machine on Exoscale
- local_action:
    module: cs_vm
    name: web-vm-1
    template='Linux Debian 7 64-bit'
    key_name='john@example.com'
    api_key='...'
    secret_key='...'
    url: https://api.exoscale.ch/compute
  register: vm

- debug: msg="ip addresses {{ item }}"
  with_items: vm.ip_addresses


# Stop a virtual machine
- local_action: cs_vm name=web-vm-1 state=stopped


# Start a virtual machine
- local_action: cs_vm name=web-vm-1 state=started


# Remove a virtual machine on CloudStack
- local_action: cs_vm name=web-vm-1 state=absent
```
