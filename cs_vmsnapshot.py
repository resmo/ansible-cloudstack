#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015, René Moser <mail@renemoser.net>
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
module: cs_vmsnapshot
short_description: Manages VM snapshots on Apache CloudStack based clouds.
description:
    - Create, remove and revert VM from snapshots.
version_added: '2.0'
author: "René Moser (@resmo)"
options:
  name:
    description:
      - Unique Name of the snapshot. In CloudStack terms C(displayname).
    required: true
    aliases: ['displayname']
  vm:
    description:
      - Name of the virtual machine.
    required: true
  description:
    description:
      - Description of the snapshot.
    required: false
    default: null
  snapshot_memory:
    description:
      - Snapshot memory if set to true.
    required: false
    default: false
  zone:
    description:
      - Name of the zone in which the VM is in. If not set, default zone is used.
    required: false
    default: null
  project:
    description:
      - Name of the project the VM is assigned to.
    required: false
    default: null
  state:
    description:
      - State of the snapshot.
    required: false
    default: 'present'
    choices: [ 'present', 'absent', 'revert' ]
  domain:
    description:
      - Domain the VM snapshot is related to.
    required: false
    default: null
  account:
    description:
      - Account the VM snapshot is related to.
    required: false
    default: null
  poll_async:
    description:
      - Poll async jobs until job has finished.
    required: false
    default: true
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
# Create a VM snapshot of disk and memory before an upgrade
- local_action:
    module: cs_vmsnapshot
    name: Snapshot before upgrade
    vm: web-01
    snapshot_memory: yes

# Revert a VM to a snapshot after a failed upgrade
- local_action:
    module: cs_vmsnapshot
    name: Snapshot before upgrade
    vm: web-01
    state: revert

# Remove a VM snapshot after successful upgrade
- local_action:
    module: cs_vmsnapshot
    name: Snapshot before upgrade
    vm: web-01
    state: absent
'''

RETURN = '''
---
name:
  description: Name of the snapshot.
  returned: success
  type: string
  sample: snapshot before update
displayname:
  description: displayname of the snapshot.
  returned: success
  type: string
  sample: snapshot before update
created:
  description: date of the snapshot.
  returned: success
  type: string
  sample: 2015-03-29T14:57:06+0200
current:
  description: true if snapshot is current
  returned: success
  type: boolean
  sample: True
state:
  description: state of the vm snapshot
  returned: success
  type: string
  sample: Allocated
type:
  description: type of vm snapshot
  returned: success
  type: string
  sample: DiskAndMemory
description:
  description:
  description: description of vm snapshot
  returned: success
  type: string
  sample: snapshot brought to you by Ansible
domain:
  description: Domain the the vm snapshot is related to.
  returned: success
  type: string
  sample: example domain
account:
  description: Account the vm snapshot is related to.
  returned: success
  type: string
  sample: example account
project:
  description: Name of project the vm snapshot is related to.
  returned: success
  type: string
  sample: Production
'''

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

# import cloudstack common
class AnsibleCloudStack:

    def __init__(self, module):
        if not has_lib_cs:
            module.fail_json(msg="python library cs required: pip install cs")

        self.result = {
            'changed': False,
        }

        self.module = module
        self._connect()

        self.domain = None
        self.account = None
        self.project = None
        self.ip_address = None
        self.zone = None
        self.vm = None
        self.os_type = None
        self.hypervisor = None
        self.capabilities = None


    def _connect(self):
        api_key = self.module.params.get('api_key')
        api_secret = self.module.params.get('secret_key')
        api_url = self.module.params.get('api_url')
        api_http_method = self.module.params.get('api_http_method')
        api_timeout = self.module.params.get('api_timeout')

        if api_key and api_secret and api_url:
            self.cs = CloudStack(
                endpoint=api_url,
                key=api_key,
                secret=api_secret,
                timeout=api_timeout,
                method=api_http_method
                )
        else:
            self.cs = CloudStack(**read_config())


    def get_or_fallback(self, key=None, fallback_key=None):
        value = self.module.params.get(key)
        if not value:
            value = self.module.params.get(fallback_key)
        return value


    # TODO: for backward compatibility only, remove if not used anymore
    def _has_changed(self, want_dict, current_dict, only_keys=None):
        return self.has_changed(want_dict=want_dict, current_dict=current_dict, only_keys=only_keys)


    def has_changed(self, want_dict, current_dict, only_keys=None):
        for key, value in want_dict.iteritems():

            # Optionally limit by a list of keys
            if only_keys and key not in only_keys:
                continue;

            # Skip None values
            if value is None:
                continue;

            if key in current_dict:

                # API returns string for int in some cases, just to make sure
                if isinstance(value, int):
                    current_dict[key] = int(current_dict[key])
                elif isinstance(value, str):
                    current_dict[key] = str(current_dict[key])

                # Only need to detect a singe change, not every item
                if value != current_dict[key]:
                    return True
        return False


    def _get_by_key(self, key=None, my_dict={}):
        if key:
            if key in my_dict:
                return my_dict[key]
            self.module.fail_json(msg="Something went wrong: %s not found" % key)
        return my_dict


    def get_project(self, key=None):
        if self.project:
            return self._get_by_key(key, self.project)

        project = self.module.params.get('project')
        if not project:
            return None
        args = {}
        args['account'] = self.get_account(key='name')
        args['domainid'] = self.get_domain(key='id')
        projects = self.cs.listProjects(**args)
        if projects:
            for p in projects['project']:
                if project.lower() in [ p['name'].lower(), p['id'] ]:
                    self.project = p
                    return self._get_by_key(key, self.project)
        self.module.fail_json(msg="project '%s' not found" % project)


    def get_ip_address(self, key=None):
        if self.ip_address:
            return self._get_by_key(key, self.ip_address)

        ip_address = self.module.params.get('ip_address')
        if not ip_address:
            self.module.fail_json(msg="IP address param 'ip_address' is required")

        args = {}
        args['ipaddress'] = ip_address
        args['account'] = self.get_account(key='name')
        args['domainid'] = self.get_domain(key='id')
        args['projectid'] = self.get_project(key='id')
        ip_addresses = self.cs.listPublicIpAddresses(**args)

        if not ip_addresses:
            self.module.fail_json(msg="IP address '%s' not found" % args['ipaddress'])

        self.ip_address = ip_addresses['publicipaddress'][0]
        return self._get_by_key(key, self.ip_address)


    def get_vm(self, key=None):
        if self.vm:
            return self._get_by_key(key, self.vm)

        vm = self.module.params.get('vm')
        if not vm:
            self.module.fail_json(msg="Virtual machine param 'vm' is required")

        args = {}
        args['account'] = self.get_account(key='name')
        args['domainid'] = self.get_domain(key='id')
        args['projectid'] = self.get_project(key='id')
        args['zoneid'] = self.get_zone(key='id')
        vms = self.cs.listVirtualMachines(**args)
        if vms:
            for v in vms['virtualmachine']:
                if vm in [ v['name'], v['displayname'], v['id'] ]:
                    self.vm = v
                    return self._get_by_key(key, self.vm)
        self.module.fail_json(msg="Virtual machine '%s' not found" % vm)


    def get_zone(self, key=None):
        if self.zone:
            return self._get_by_key(key, self.zone)

        zone = self.module.params.get('zone')
        zones = self.cs.listZones()

        # use the first zone if no zone param given
        if not zone:
            self.zone = zones['zone'][0]
            return self._get_by_key(key, self.zone)

        if zones:
            for z in zones['zone']:
                if zone in [ z['name'], z['id'] ]:
                    self.zone = z
                    return self._get_by_key(key, self.zone)
        self.module.fail_json(msg="zone '%s' not found" % zone)


    def get_os_type(self, key=None):
        if self.os_type:
            return self._get_by_key(key, self.zone)

        os_type = self.module.params.get('os_type')
        if not os_type:
            return None

        os_types = self.cs.listOsTypes()
        if os_types:
            for o in os_types['ostype']:
                if os_type in [ o['description'], o['id'] ]:
                    self.os_type = o
                    return self._get_by_key(key, self.os_type)
        self.module.fail_json(msg="OS type '%s' not found" % os_type)


    def get_hypervisor(self):
        if self.hypervisor:
            return self.hypervisor

        hypervisor = self.module.params.get('hypervisor')
        hypervisors = self.cs.listHypervisors()

        # use the first hypervisor if no hypervisor param given
        if not hypervisor:
            self.hypervisor = hypervisors['hypervisor'][0]['name']
            return self.hypervisor

        for h in hypervisors['hypervisor']:
            if hypervisor.lower() == h['name'].lower():
                self.hypervisor = h['name']
                return self.hypervisor
        self.module.fail_json(msg="Hypervisor '%s' not found" % hypervisor)


    def get_account(self, key=None):
        if self.account:
            return self._get_by_key(key, self.account)

        account = self.module.params.get('account')
        if not account:
            return None

        domain = self.module.params.get('domain')
        if not domain:
            self.module.fail_json(msg="Account must be specified with Domain")

        args = {}
        args['name'] = account
        args['domainid'] = self.get_domain(key='id')
        args['listall'] = True
        accounts = self.cs.listAccounts(**args)
        if accounts:
            self.account = accounts['account'][0]
            return self._get_by_key(key, self.account)
        self.module.fail_json(msg="Account '%s' not found" % account)


    def get_domain(self, key=None):
        if self.domain:
            return self._get_by_key(key, self.domain)

        domain = self.module.params.get('domain')
        if not domain:
            return None

        args = {}
        args['listall'] = True
        domains = self.cs.listDomains(**args)
        if domains:
            for d in domains['domain']:
                if d['path'].lower() in [ domain.lower(), "root/" + domain.lower(), "root" + domain.lower() ] :
                    self.domain = d
                    return self._get_by_key(key, self.domain)
        self.module.fail_json(msg="Domain '%s' not found" % domain)


    def get_tags(self, resource=None):
        existing_tags = self.cs.listTags(resourceid=resource['id'])
        if existing_tags:
            return existing_tags['tag']
        return []


    def _delete_tags(self, resource, resource_type, tags):
        existing_tags = resource['tags']
        tags_to_delete = []
        for existing_tag in existing_tags:
            if existing_tag['key'] in tags:
                if existing_tag['value'] != tags[key]:
                    tags_to_delete.append(existing_tag)
            else:
                tags_to_delete.append(existing_tag)
        if tags_to_delete:
            self.result['changed'] = True
            if not self.module.check_mode:
                args = {}
                args['resourceids']  = resource['id']
                args['resourcetype'] = resource_type
                args['tags']         = tags_to_delete
                self.cs.deleteTags(**args)


    def _create_tags(self, resource, resource_type, tags):
        tags_to_create = []
        for i, tag_entry in enumerate(tags):
            tag = {
                'key':   tag_entry['key'],
                'value': tag_entry['value'],
            }
            tags_to_create.append(tag)
        if tags_to_create:
            self.result['changed'] = True
            if not self.module.check_mode:
                args = {}
                args['resourceids']  = resource['id']
                args['resourcetype'] = resource_type
                args['tags']         = tags_to_create
                self.cs.createTags(**args)


    def ensure_tags(self, resource, resource_type=None):
        if not resource_type or not resource:
            self.module.fail_json(msg="Error: Missing resource or resource_type for tags.")

        if 'tags' in resource:
            tags = self.module.params.get('tags')
            if tags is not None:
                self._delete_tags(resource, resource_type, tags)
                self._create_tags(resource, resource_type, tags)
                resource['tags'] = self.get_tags(resource)
        return resource


    def get_capabilities(self, key=None):
        if self.capabilities:
            return self._get_by_key(key, self.capabilities)
        capabilities = self.cs.listCapabilities()
        self.capabilities = capabilities['capability']
        return self._get_by_key(key, self.capabilities)


    # TODO: for backward compatibility only, remove if not used anymore
    def _poll_job(self, job=None, key=None):
        return self.poll_job(job=job, key=key)


    def poll_job(self, job=None, key=None):
        if 'jobid' in job:
            while True:
                res = self.cs.queryAsyncJobResult(jobid=job['jobid'])
                if res['jobstatus'] != 0 and 'jobresult' in res:
                    if 'errortext' in res['jobresult']:
                        self.module.fail_json(msg="Failed: '%s'" % res['jobresult']['errortext'])
                    if key and key in res['jobresult']:
                        job = res['jobresult'][key]
                    break
                time.sleep(2)
        return job


class AnsibleCloudStackVmSnapshot(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)


    def get_snapshot(self):
        args                        = {}
        args['virtualmachineid']    = self.get_vm('id')
        args['account']             = self.get_account('name')
        args['domainid']            = self.get_domain('id')
        args['projectid']           = self.get_project('id')
        args['name']                = self.module.params.get('name')

        snapshots = self.cs.listVMSnapshot(**args)
        if snapshots:
            return snapshots['vmSnapshot'][0]
        return None


    def create_snapshot(self):
        snapshot = self.get_snapshot()
        if not snapshot:
            self.result['changed'] = True

            args                        = {}
            args['virtualmachineid']    = self.get_vm('id')
            args['name']                = self.module.params.get('name')
            args['description']         = self.module.params.get('description')
            args['snapshotmemory']      = self.module.params.get('snapshot_memory')

            if not self.module.check_mode:
                res = self.cs.createVMSnapshot(**args)

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                poll_async = self.module.params.get('poll_async')
                if res and poll_async:
                    snapshot = self._poll_job(res, 'vmsnapshot')

        return snapshot


    def remove_snapshot(self):
        snapshot = self.get_snapshot()
        if snapshot:
            self.result['changed'] = True
            if not self.module.check_mode:
                res = self.cs.deleteVMSnapshot(vmsnapshotid=snapshot['id'])

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                poll_async = self.module.params.get('poll_async')
                if res and poll_async:
                    res = self._poll_job(res, 'vmsnapshot')
        return snapshot


    def revert_vm_to_snapshot(self):
        snapshot = self.get_snapshot()
        if snapshot:
            self.result['changed'] = True

            if snapshot['state'] != "Ready":
                self.module.fail_json(msg="snapshot state is '%s', not ready, could not revert VM" % snapshot['state'])

            if not self.module.check_mode:
                res = self.cs.revertToVMSnapshot(vmsnapshotid=snapshot['id'])

                poll_async = self.module.params.get('poll_async')
                if res and poll_async:
                    res = self._poll_job(res, 'vmsnapshot')
            return snapshot

        self.module.fail_json(msg="snapshot not found, could not revert VM")


    def get_result(self, snapshot):
        if snapshot:
            if 'displayname' in snapshot:
                self.result['displayname'] = snapshot['displayname']
            if 'created' in snapshot:
                self.result['created'] = snapshot['created']
            if 'current' in snapshot:
                self.result['current'] = snapshot['current']
            if 'state' in snapshot:
                self.result['state'] = snapshot['state']
            if 'type' in snapshot:
                self.result['type'] = snapshot['type']
            if 'name' in snapshot:
                self.result['name'] = snapshot['name']
            if 'description' in snapshot:
                self.result['description'] = snapshot['description']
            if 'domain' in snapshot:
                self.result['domain'] = snapshot['domain']
            if 'account' in snapshot:
                self.result['account'] = snapshot['account']
            if 'project' in snapshot:
                self.result['project'] = snapshot['project']
        return self.result


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True, aliases=['displayname']),
            vm = dict(required=True),
            description = dict(default=None),
            zone = dict(default=None),
            snapshot_memory = dict(choices=BOOLEANS, default=False),
            state = dict(choices=['present', 'absent', 'revert'], default='present'),
            domain = dict(default=None),
            account = dict(default=None),
            project = dict(default=None),
            poll_async = dict(choices=BOOLEANS, default=True),
            api_key = dict(default=None),
            api_secret = dict(default=None, no_log=True),
            api_url = dict(default=None),
            api_http_method = dict(choices=['get', 'post'], default='get'),
            api_timeout = dict(type='int', default=10),
        ),
        required_together = (
            ['icmp_type', 'icmp_code'],
            ['api_key', 'api_secret', 'api_url'],
        ),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_vmsnapshot = AnsibleCloudStackVmSnapshot(module)

        state = module.params.get('state')
        if state in ['revert']:
            snapshot = acs_vmsnapshot.revert_vm_to_snapshot()
        elif state in ['absent']:
            snapshot = acs_vmsnapshot.remove_snapshot()
        else:
            snapshot = acs_vmsnapshot.create_snapshot()

        result = acs_vmsnapshot.get_result(snapshot)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
