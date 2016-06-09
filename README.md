Ansible CloudStack Modules
==========================

Manages resources on Apache CloudStack, Citrix CloudPlatform and Exoscale.

**NOTE: Since Ansible 2.1 was released, I don't see any more need to maintain this repo for Ansible 1.9. I mark this repo as deprecated with the next Ansible major release 2.2**


Difference of CloudStack modules in ansible-modules-extras and this repo?
--------------------------------------------------------------------------
This repo has been made for simple using CloudStack modules while ansible 2.0 is not yet released. 
I maintain the CloudStack modules in *ansible-modules-extras* as well and I am in charge to keep them in sync.

**This means they are 100% compatible**.

If you like to contribute, it would be fine to make PRs here first. After acceptance you should also make a PR to ansible-modules-extras (or let me know if I should do it.)

AnsibleCloudStack (called utils) in upstream Ansible is located in *ansible* repo [here](https://github.com/ansible/ansible/blob/devel/lib/ansible/module_utils/cloudstack.py) and will be imported in *ansible-modules-extras* (once ansible 2.0 is released). 

I also sync changes between the utils in upstream ansible and *ansible_cloudstack_utils.py*, but unfortunately I didn't find a way to import *ansible_cloudstack_utils.py* in the module here. 

(If you know how this would be possible I would be more then happy). 

That is why I just copied it into the modules. Same here, if you make changes to utils make it in *ansible_cloudstack_utils.py* and I will spread it to all modules (I have my tools ready for doing this).


Requirements
------------
Uses Exosclale's python cs library: `sudo pip install cs`

Note: You can pass the API credentials by module arguments `api_url`, `api_key` and `api_secret` or even more comfortable by `cloudstack.ini`. Please see the https://github.com/exoscale/cs for more information.


Examples
--------

~~~yaml
# Upload an ISO (Note: this should have CloudStack SSH PubKey handling installed):
- local_action:
     module: cs_iso:
     name: Debian 7 64-bit
     url: http://iso.example.com/debian-cd/7.7.0/amd64/iso-cd/debian-7.7.0-amd64-netinst.iso
     os_type: Debian GNU/Linux 7(64-bit)
     checksum: 0b31bccccb048d20b551f70830bb7ad0


# Upload your SSH public key
- local_action:
    module: cs_sshkeypair
    name: john@example.com
    public_key: '{{ lookup('file', '~/.ssh/id_rsa.pub') }}'


# Ensure security group default exists
- local_action: 
    module: cs_securitygroup
    name: default


# Add inbound tcp rules to security group default
- local_action: 
    module: cs_securitygroup_rule
    security_group: default
    start_port: '{{ item }}'
    end_port: '{{ item }}'
  with_items:
  - 80
  - 8089


# Create a virtual machine on CloudStack
- local_action:
    module: cs_instance
    name: web-vm-1
    iso: Linux Debian 7 64-bit
    hypervisor: VMware
    service_offering: Tiny
    disk_offering: Performance
    disk_size: 20
    ssh_key: john@example.com


# Make a snapshot
- local_action:
    module: cs_vmsnapshot
    name: Snapshot before upgrade
    vm: web-vm-1
    snapshot_memory: yes


# Change service offering on existing VM
- local_action:
    module: cs_instance
    name: web-vm-1
    service_offering: Medium


# Stop a virtual machine
- local_action:
    module: cs_instance
    name: web-vm-1
    state: stopped


# Start a virtual machine
- local_action: cs_instance name=web-vm-1 state=started


# Remove a virtual machine on CloudStack
- local_action: cs_instance name=web-vm-1 state=absent
~~~
