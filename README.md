Ansible Cloudstack Modules
==========================

Manages resources on Apache CloudStack, Citrix CloudPlatform and Exoscale.

Requirements
------------
Uses Exosclale's python cs library: `sudo pip install cs`

Note: You can pass the API credentials by module arguments `api_url`, `api_key` and `api_secret` or even more comfortable by `cloudstack.ini`. Please see the https://github.com/exoscale/cs for more information.


Examples
--------

~~~yaml
# Upload an ISO (Note: this should have CloudStack SSH PubKey handling installed):
- local_action:
     module: cloudstack_iso:
     name: Debian 7 64-bit
     url: http://iso.example.com/debian-cd/7.7.0/amd64/iso-cd/debian-7.7.0-amd64-netinst.iso
     os_type: Debian GNU/Linux 7(64-bit)
     checksum: 0b31bccccb048d20b551f70830bb7ad0


# Upload your SSH public key
- local_action:
    module: cloudstack_sshkey
    name: john@example.com
    public_key: '{{ lookup('file', '~/.ssh/id_rsa.pub') }}'


# Ensure security group default exists
- local_action: 
    module: cloudstack_sg
    name: default


# Add inbound tcp rules to security group default
- local_action: 
    module: cloudstack_sg_rule
    name: default
    start_port: '{{ item }}'
    end_port: '{{ item }}'
  with_items:
  - 80
  - 8089


# Create a virtual machine on CloudStack
- local_action:
    module: cloudstack_vm
    name: web-vm-1
    iso: Linux Debian 7 64-bit
    hypervisor: VMware
    service_offering: Tiny
    disk_offering: Performance
    disk_size: 20
    ssh_key: john@example.com


# Make a snapshot
- local_action:
    module: cloudstack_vmsnapshot
    name: Snapshot before upgrade
    vm: web-vm-1
    snapshot_memory: yes


# Change service offering on existing VM
- local_action:
    module: cloudstack_vm
    name: web-vm-1
    service_offering: Medium


# Stop a virtual machine
- local_action:
    module: cloudstack_vm
    name: web-vm-1
    state: stopped


# Start a virtual machine
- local_action: cloudstack_vm name=web-vm-1 state=started


# Remove a virtual machine on CloudStack
- local_action: cloudstack_vm name=web-vm-1 state=absent
~~~
