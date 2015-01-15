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
module: cloudstack_vmsnapshot
short_description: Create, revert to and delete VM snapshots on Apache CloudStack based clouds.
description:
    - Manage VM snapshots on Apache CloudStack, Citrix CloudPlatform and Exoscale.
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), C(api_http_method), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  name:
    description:
      - Name of the snapshot. In CloudStack terms C(displayname). We assume this name is unique.
    required: true
    default: null
    aliases: []
  description:
    description:
      - Description of the snapshot.
    required: false
    default: 'Snapshot by Ansible'
    aliases: []
  snapshot_memory:
    description:
      - Snapshot memory if set to true.
    required: false
    default: false
    aliases: []
  project:
    description:
      - Name of the project the VM is in.
    required: false
    default: null
    aliases: []
  state:
    description:
      - State of the snapshot.
    required: false
    default: 'present'
    choices: [ 'present', 'absent', 'reverted' ]
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
requirements: [ 'cs' ]
'''

EXAMPLES = '''
---
# Create a VM snapshot of disk and memory before an upgrade
- cloudstack_vmsnapshot:
     name: Snapshot before upgrade
     vm: web-01
     snapshot_memory: yes


# Revert a VM to a snapshot after a failed upgrade
- cloudstack_vmsnapshot:
     name: Snapshot before upgrade
     vm: web-01
     state: reverted


# Remove a VM snapshot after successful upgrade
- cloudstack_vmsnapshot:
     name: Snapshot before upgrade
     vm: web-01
     state: absent
'''

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required. pip install cs'")
    sys.exit(1)


def get_project_id(module, cs):
    project = module.params.get('project')
    if not project:
        return None

    projects = cs.listProjects()
    if projects:
        for p in projects['project']:
            if p['name'] == project or p['id'] == project:
                return p['id']
    module.fail_json(msg="Project '%s' not found" % project)


def get_vm_id(module, cs):
    vm = module.params.get('vm')
    project_id = get_project_id(module, cs)
    vms = cs.listVirtualMachines(projectid=project_id)
    if vms:
        for v in vms['virtualmachine']:
            if v['name'] == vm or v['id'] == vm:
                return v['id']
    module.fail_json(msg="Virtual machine '%s' not found" % vm)


def get_snapshot(module, cs, vm_id):
    args = {}
    args['virtualmachineid'] = vm_id
    args['name'] = module.params.get('name')
    snapshots = cs.listVMSnapshot(**args)
    if snapshots:
        return snapshots['vmSnapshot'][0]
    return None


def create_snapshot(module, cs, result, snapshot, vm_id):
    if not snapshot:
        args = {}
        args['virtualmachineid'] = vm_id
        args['name'] = module.params.get('name')
        args['description'] = module.params.get('description')
        args['snapshotmemory'] = module.params.get('snapshot_memory')
        if not module.check_mode:
            res = cs.createVMSnapshot(**args)
            poll_async = module.params.get('poll_async')
            if poll_async:
                snapshot = poll_job(cs, res, 'vmsnapshot')
            else:
                snapshot = res['vmsnapshot']
        result['changed'] = True
    return (result, snapshot)


def remove_snapshot(module, cs, result, snapshot):
    if snapshot:
        result['changed'] = True
        if not module.check_mode:
            res = cs.deleteVMSnapshot(vmsnapshotid=snapshot['id'])
            poll_async = module.params.get('poll_async')
            if poll_async:
                poll_job(cs, res, 'vmsnapshot')
    return (result, snapshot)


def revert_vm_to_snapshot(module, cs, result, snapshot):
    if snapshot:
        result['changed'] = True
        if not module.check_mode:
            res = cs.revertToVMSnapshot(vmsnapshotid=snapshot['id'])
            poll_async = module.params.get('poll_async')
            if poll_async:
                poll_job(cs, res, 'vmsnapshot')
    return (result, snapshot)


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


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True, default=None),
            vm = dict(required=True, default=None),
            description = dict(default='Snapshot by Ansible'),
            project = dict(default=None),
            snapshot_memory = dict(choices=BOOLEANS, default=False),
            state = dict(choices=['present', 'absent', 'reverted'], default='present'),
            poll_async = dict(choices=BOOLEANS, default=True),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
        ),
        supports_check_mode=True
    )

    result = {}
    result['changed'] = False
    state = module.params.get('state')

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

        vm_id = get_vm_id(module, cs)
        snapshot = get_snapshot(module, cs, vm_id)
        
        if state in ['absent']:
            (result, snapshot) = remove_snapshot(module, cs, result, snapshot)
        elif state in ['reverted']:
            (result, snapshot) = revert_vm_to_snapshot(module, cs, result, snapshot)
        else:
            (result, snapshot) = create_snapshot(module, cs, result, snapshot, vm_id)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    if snapshot:
        if 'displayname' in snapshot:
            result['displayname'] = snapshot['displayname']
        if 'created' in snapshot:
            result['created'] = snapshot['created']
        if 'current' in snapshot:
            result['current'] = snapshot['current']
        if 'state' in snapshot:
            result['state'] = snapshot['state']
        if 'type' in snapshot:
            result['type'] = snapshot['type']
        if 'name' in snapshot:
            result['name'] = snapshot['name']
    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
