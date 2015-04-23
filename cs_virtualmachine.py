#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2014, René Moser <mail@renemoser.net>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: cloudstack_vm
short_description: Create, start, scale, restart, stop and destroy virtual machines on Apache CloudStack based clouds.
description:
    - Manage virtual machines on Apache CloudStack, Citrix CloudPlatform and Exoscale. Existing virtual machines will be scaled if service offering is different by stopping and starting the virtual machine.
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), C(api_http_method), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  name:
    description:
      - Name of the virtual machine. Name can only contain ASCII letters. Either C(name) or C(display_name) is required.
    required: false
    default: null
    aliases: []
  display_name:
    description:
      - Custom display name of the virtual machine. Either C(name) or C(display_name) is required.
    required: false
    default: null
    aliases: []
  group:
    description:
      - Group in where the new virtual machine should be in.
    required: false
    default: null
    aliases: []
  state:
    description:
      - State of the virtual machine.
    required: false
    default: 'present'
    choices: [ 'created', 'started', 'running', 'booted', 'stopped', 'halted', 'restarted', 'rebooted', 'present', 'absent', 'destroyed', 'expunged' ]
    aliases: []
  service_offering:
    description:
      - Name or id of the service offering of the new virtual machine. If not set, first found service offering is used.
    required: false
    default: null
    aliases: []
  template:
    description:
      - Name or id of the template to be used for creating the new virtual machine. Required when using C(state=created). Mutually exclusive with C(ISO) option.
    required: false
    default: null
    aliases: []
  iso:
    description:
      - Name or id of the ISO to be used for creating the new virtual machine. Required when using C(state=created). Mutually exclusive with C(template) option.
    required: false
    default: null
    aliases: []
  hypervisor:
    description:
      - Name the hypervisor to be used for creating the new virtual machine. Relevant when using C(state=created) and option C(ISO) is used. If not set, first found hypervisor will be used.
    required: false
    default: null
    choices: [ 'KVM', 'VMware', 'BareMetal', 'XenServer', 'LXC', 'HyperV', 'UCS', 'OVM' ]
    aliases: []
  networks:
    description:
      - List of networks to use for the new virtual machine.
    required: false
    default: []
    aliases: []
  ipaddress:
    description:
      - the ip address for default vm's network.
    required: false
    default: null
    aliases: []
  disk_offering:
    description:
      - Name of the disk offering to be used.
    required: false
    default: null
    aliases: []
  disk_size:
    description:
      - Disk size in GByte required if deploying virtual machine from ISO.
    required: false
    default: null
    aliases: []
  security_groups:
    description:
      - List of security groups the virtual machine to be applied to.
    required: false
    default: []
    aliases: [ 'security_group' ]
  project:
    description:
      - Name of the project the virtual machine to be created in.
    required: false
    default: null
    aliases: []
  zone:
    description:
      - Name of the zone in which the virtual machine shoud be created. If not set, default zone is used.
    required: false
    default: null
    aliases: []
  ssh_key:
    description:
      - Name of the SSH key to be deployed on the new virtual machine.
    required: false
    default: null
    aliases: []
  affinity_groups:
    description:
      - Affinity groups names to be applied to the new virtual machine.
    required: false
    default: null
    aliases: [ 'affinity_group' ]
  user_data:
    description:
      - Optional data (ASCII) that can be sent to the virtual machine upon a successful deployment. The data will be automatically base64 encoded, consider switching to HTTP_POST by using C(CLOUDSTACK_METHOD=post) to increase the HTTP_GET size limit of 2KB to 32 KB.
    required: false
    default: null
    aliases: []
  poll_async:
    description:
      - Poll async jobs until job has finised.
    required: false
    default: true
    aliases: []
  api_key:
    description:
      - API key of the CloudStack API.
    required: false
    default: null
    aliases: []
  api_secret:
    description:
      - Secret key of the CloudStack API.
    required: false
    default: null
    aliases: []
  api_url:
    description:
      - URL of the CloudStack API e.g. https://cloud.example.com/client/api.
    required: false
    default: null
    aliases: []
  api_http_method:
    description:
      - HTTP method used.
    required: false
    default: 'get'
    aliases: []
author: René Moser
requirements: [ 'python library C(cs)' ]
'''

EXAMPLES = '''
---
# Create a virtual machine on CloudStack from an ISO
# NOTE: Offering and ISO names depending on the CloudStack configuration.
- local_action:
    module: cloudstack_vm
    name: web-vm-1
    iso: Linux Debian 7 64-bit
    hypervisor: VMware
    service_offering: 1cpu_1gb
    disk_offering: PerfPlus Storage
    disk_size: '20'
    api_key: ...
    api_secret: ...
    api_url: https://cloud.example.com/client/api


# Create a virtual machine on Exoscale Public Cloud
- local_action:
    module: cloudstack_vm
    name: web-vm-1
    template: Linux Debian 7 64-bit
    service_offering: Tiny
    ssh_key: john@example.com
    api_key: ...
    api_secret: ...
    api_url: https://api.exoscale.ch/compute
  register: vm

- debug: msg='default ip {{ vm.default_ip }} and is in state {{ vm.vm_state }}'


# Stop a virtual machine, credentials used in $HOME/.cloudstack.ini
- local_action: cloudstack_vm name=web-vm-1 state=stopped


# Start a virtual machine, credentials used in $HOME/.cloudstack.ini
- local_action: cloudstack_vm name=web-vm-1 state=started


# Remove a virtual machine, credentials used in $HOME/.cloudstack.ini
- local_action: cloudstack_vm name=web-vm-1 state=absent
'''

import sys
import base64

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required: pip install cs'")
    sys.exit(1)


def get_service_offering_id(module, cs):
    service_offering = module.params.get('service_offering')
    service_offerings = cs.listServiceOfferings()
    if service_offerings:
        if not service_offering:
            return service_offerings['serviceoffering'][0]['id']

        for s in service_offerings['serviceoffering']:
            if s['name'] == service_offering or s['id'] == service_offering:
                return s['id']
    module.fail_json(msg="Service offering '%s' not found" % service_offering)


def get_template_or_iso_id(module, cs):
    template = module.params.get('template')
    iso = module.params.get('iso')

    if not template and not iso:
        module.fail_json(msg="template or iso is required.")

    if template and iso:
        module.fail_json(msg="template are iso are mutually exclusive.")

    if template:
        templates = cs.listTemplates(templatefilter='executable')
        if templates:
            for t in templates['template']:
                if t['displaytext'] == template or t['name'] == template or t['id'] == template:
                    return t['id']
        module.fail_json(msg="template '%s' not found" % template)

    elif iso:
        isos = cs.listIsos()
        if isos:
            for i in isos['iso']:
                if i['displaytext'] == iso or i['name'] == iso or i['id'] == iso:
                    return i['id']
        module.fail_json(msg="iso '%s' not found" % iso)


def get_disk_offering_id(module, cs):
    disk_offering = module.params.get('disk_offering')

    if not disk_offering:
        return ''

    disk_offerings = cs.listDiskOfferings()
    if disk_offerings:
        for d in disk_offerings['diskoffering']:
            if d['name'] == disk_offering or d['id'] == disk_offering:
                return d['id']
    module.fail_json(msg="disk offering '%s' not found" % disk_offering)


def get_project_id(module, cs):
    project = module.params.get('project')
    if not project:
        return ''

    projects = cs.listProjects()
    if projects:
        for p in projects['project']:
            if p['name'] == project or p['displaytext'] == project or p['id'] == project:
                return p['id']
    module.fail_json(msg="project '%s' not found" % project)


def get_zone_id(module, cs):
    zone = module.params.get('zone')
    zones = cs.listZones()

    if not zone:
        return zones['zone'][0]['id']

    if zones:
        for z in zones['zone']:
            if z['name'] == zone or z['id'] == zone:
                return z['id']
    module.fail_json(msg="zone '%s' not found" % zone)


def get_hypervisor(module, cs):
    hypervisor = module.params.get('hypervisor')
    hypervisors = cs.listHypervisors()

    if not hypervisor:
        return hypervisors['hypervisor'][0]['name']

    if hypervisors:
        for h in hypervisors['hypervisor']:
            if h['name'] == hypervisor:
                return h['name']
    module.fail_json(msg="hypervisor '%s' not available" % hypervisor)


def get_vm(module, cs, project_id):
    vm_name = module.params.get('name')
    vm_display_name = module.params.get('display_name')

    vms = cs.listVirtualMachines(projectid=project_id)
    if vms:
        for v in vms['virtualmachine']:
            if ('name' in v and v['name'] == vm_name) or ('displayname' in v and v['displayname'] == vm_display_name):
                return v
    return None


def get_network_ids(module, cs, project_id):
    networks = module.params.get('networks')

    if not networks:
        return None

    zone_id = get_zone_id(module, cs)
    if project_id:
        network_res = cs.listNetworks(projectid=project_id, zoneid=zone_id)
    else:
        network_res = cs.listNetworks(zoneid=zone_id)

    network_ids = []
    if network_res:
        for n in network_res['network']:
            if n['name'] in networks or n['id'] in networks:
                network_ids.append(n['id'])
    return ','.join(network_ids)


def poll_job(cs, job, key):
    if 'jobid' in job:
        while True:
            res = cs.queryAsyncJobResult(jobid=job['jobid'])
            if res['jobstatus'] != 0:
                if 'jobresult' in res and key in res['jobresult']:
                    job = res['jobresult'][key]
                break
            time.sleep(2)
    return job


def create_vm(module, cs, result, vm, project_id):
    if not vm:
        args = {}
        args['templateid']          = get_template_or_iso_id(module, cs)
        args['zoneid']              = get_zone_id(module, cs)
        args['serviceofferingid']   = get_service_offering_id(module, cs)
        args['projectid']           = project_id
        args['networkids']          = get_network_ids(module, cs, project_id)
        args['diskofferingid']      = get_disk_offering_id(module, cs)
        args['hypervisor']          = get_hypervisor(module, cs)

        args['name']                = module.params.get('name')
        args['group']               = module.params.get('group')
        args['keypair']             = module.params.get('ssh_key')
        args['size']                = module.params.get('disk_size')

        user_data = module.params.get('user_data')
        if user_data:
            args['userdata'] = base64.b64encode(user_data)

        display_name = module.params.get('display_name')
        if not display_name:
            display_name = args['name']
        args['displayname'] = display_name

        security_group_name_list = module.params.get('security_groups')
        security_group_names = ''
        if security_group_name_list:
            security_group_names = ','.join(security_group_name_list)
        args['securitygroupnames'] = security_group_names

        affinity_group_name_list = module.params.get('affinity_groups')
        affinity_group_names = ''
        if affinity_group_name_list:
            affinity_group_names = ','.join(affinity_group_name_list)
        args['affinitygroupnames'] = affinity_group_names

        ipaddress = module.params.get('ipaddress')
        if ipaddress:
            args['ipaddress'] = ipaddress

        if not module.check_mode:
            vm = cs.deployVirtualMachine(**args)

            if 'errortext' in vm:
                module.fail_json(msg="Failed: '%s'" % vm['errortext'])

            poll_async = module.params.get('poll_async')
            if poll_async:
                vm = poll_job(cs, vm, 'virtualmachine')

        result['changed'] = True
    return (result, vm)


def scale_vm(module, cs, result, vm):
    if vm:
        service_offering_id = get_service_offering_id(module, cs)
        if vm['serviceofferingid'] != service_offering_id:
            if not module.check_mode:
                vm_state = vm['state']
                (result, vm) = stop_vm(module, cs, result, vm)
                vm = poll_vm_job(vm, cs)
                cs.scaleVirtualMachine(id=vm['id'], serviceofferingid=service_offering_id)
                # Start VM again if it ran before the scaling
                if vm_state == 'Running':
                    (result, vm) = start_vm(module, cs, result, vm)
                    vm = poll_job(cs, vm, 'virtualmachine')
            result['changed'] = True
    return (result, vm)


def remove_vm(module, cs, result, vm):
    if vm:
        if vm['state'] not in [ 'expunging', 'destroying', 'destroyed' ]:
            result['changed'] = True
            if not module.check_mode:
                res = cs.destroyVirtualMachine(id=vm['id'])
                if 'errortext' in res:
                    module.fail_json(msg="Failed: '%s'" % res['errortext'])

                poll_async = module.params.get('poll_async')
                if poll_async:
                    vm = poll_job(cs, res, 'virtualmachine')

    return (result, vm)


def expunge_vm(module, cs, result, vm):
    if vm:
        res = {}
        if vm['state'] in [ 'destroying', 'destroyed' ]:
            result['changed'] = True
            if not module.check_mode:
                res = cs.expungeVirtualMachine(id=vm['id'])

        elif vm['state'] not in [ 'expunging' ]:
            result['changed'] = True
            if not module.check_mode:
                res = cs.destroyVirtualMachine(id=vm['id'], expunge=True)

        if res and 'errortext' in res:
            module.fail_json(msg="Failed: '%s'" % res['errortext'])

        poll_async = module.params.get('poll_async')
        if poll_async:
            vm = poll_job(cs, res, 'virtualmachine')

    return (result, vm)


def stop_vm(module, cs, result, vm):
    if not vm:
        module.fail_json(msg="Virtual machine named '%s' not found" % module.params.get('name'))

    if vm['state'] != 'Stopped' and vm['state'] != 'Stopping':
        if not module.check_mode:
            vm = cs.stopVirtualMachine(id=vm['id'])
            if 'errortext' in vm:
                module.fail_json(msg="Failed: '%s'" % vm['errortext'])
            poll_async = module.params.get('poll_async')
            if poll_async:
                vm = poll_job(cs, vm, 'virtualmachine')

        result['changed'] = True
    return (result, vm)


def start_vm(module, cs, result, vm):
    if not vm:
        module.fail_json(msg="Virtual machine named '%s' not found" % module.params.get('name'))
    if vm['state'] == 'Stopped' or vm['state'] == 'Stopping':
        if not module.check_mode:
            vm = cs.startVirtualMachine(id=vm['id'])
            if 'errortext' in vm:
                module.fail_json(msg="Failed: '%s'" % vm['errortext'])
            poll_async = module.params.get('poll_async')
            if poll_async:
                vm = poll_job(cs, vm, 'virtualmachine')

        result['changed'] = True
    return (result, vm)


def restart_vm(module, cs, result, vm):
    if not vm:
        module.fail_json(msg="Virtual machine named '%s' not found" % module.params.get('name'))
    if vm['state'] == 'Running' or vm['state'] == 'Starting':
        if not module.check_mode:
            vm = cs.rebootVirtualMachine(id=vm['id'])
            poll_async = module.params.get('poll_async')
            if poll_async:
                vm = poll_job(cs, vm, 'virtualmachine')

        result['changed'] = True
    elif vm['state'] == 'Stopping' or vm['state'] == 'Stopped':
        module.fail_json(msg="Virtual machine named '%s' not running, not restarted" % module.params.get('name'))
    return (result, vm)


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(default=None),
            display_name = dict(default=None),
            group = dict(default=None),
            state = dict(choices=['created', 'started', 'running', 'booted', 'stopped', 'halted', 'restarted', 'rebooted', 'present', 'absent', 'destroyed', 'expunged'], default='present'),
            service_offering = dict(default=None),
            template = dict(default=None),
            iso = dict(default=None),
            networks = dict(type='list', default=None),
            ipaddress = dict(default=None),
            disk_offering = dict(default=None),
            disk_size = dict(default=None),
            hypervisor = dict(default=None),
            security_groups = dict(type='list', aliases= [ 'security_group' ], default=None),
            affinity_groups = dict(type='list', aliases= [ 'affinity_group' ], default=None),
            project = dict(default=None),
            user_data = dict(default=None),
            zone = dict(default=None),
            poll_async = dict(choices=BOOLEANS, default=True),
            ssh_key = dict(default=None),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
        ),
        required_one_of = (
            ['name', 'display_name'],
        ),
        supports_check_mode=True
    )

    result = {}
    state = module.params.get('state')
    result['changed'] = False

    try:
        api_key = module.params.get('api_key')
        api_secret = module.params.get('secret_key')
        api_url = module.params.get('api_url')
        api_http_method = module.params.get('api_http_method')

        if api_key and api_secret and api_url:
            cs = CloudStack(
                endpoint=api_url,
                key=api_key,
                secret=api_secret,
                method=api_http_method
                )
        else:
            cs = CloudStack(**read_config())

        project_id = get_project_id(module, cs)
        vm = get_vm(module, cs, project_id)

        if state in ['absent', 'destroyed']:
            (result, vm) = remove_vm(module, cs, result, vm)

        elif state in ['expunged']:
            (result, vm) = expunge_vm(module, cs, result, vm)

        elif state in ['present', 'created']:
            if not vm:
                (result, vm) = create_vm(module, cs, result, vm, project_id)
            else:
                (result, vm) = scale_vm(module, cs, result, vm)

        elif state in ['stopped', 'halted']:
            (result, vm) = stop_vm(module, cs, result, vm)

        elif state in ['started', 'running', 'booted']:
            (result, vm) = start_vm(module, cs, result, vm)

        elif state in ['restarted', 'rebooted']:
            (result, vm) = restart_vm(module, cs, result, vm)

        if vm:

            if 'state' in vm and vm['state'] == 'Error':
                module.fail_json(msg="Virtual machine named '%s' in error state." % module.params.get('name'))

            if 'id' in vm:
                result['id'] = vm['id']

            if 'name' in vm:
                result['name'] = vm['name']

            if 'displayname' in vm:
                result['display_name'] = vm['displayname']

            if 'group' in vm:
                result['group'] = vm['group']

            if 'password' in vm:
                result['password'] = vm['password']

            if 'serviceofferingname' in vm:
                result['service_offering'] = vm['serviceofferingname']

            if 'zonename' in vm:
                result['zone'] = vm['zonename']

            if 'templatename' in vm:
                result['template'] = vm['templatename']

            if 'isoname' in vm:
                result['iso'] = vm['isoname']

            if 'created' in vm:
                result['created'] = vm['created']

            if 'state' in vm:
                result['vm_state'] = vm['state']

            if 'tags' in vm:
                tags = {}
                for tag in vm['tags']:
                    key = tag['key']
                    value = tag['value']
                    tags[key] = value
                result['tags'] = tags

            if 'nic' in vm:
                for nic in vm['nic']:
                    if nic['isdefault']:
                        result['default_ip'] = nic['ipaddress']
                result['nic'] = vm['nic']

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
