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
module: cs_affinitygroup
short_description: Manages affinity groups on Apache CloudStack based clouds.
description: Create and remove affinity groups.
version_added: '2.0'
author: René Moser
options:
  name:
    description:
      - Name of the affinity group.
    required: true
  affinty_type:
    description:
      - Type of the affinity group. If not specified, first found affinity type is used.
    required: false
    default: null
  description:
    description:
      - Description of the affinity group.
    required: false
    default: null
  state:
    description:
      - State of the affinity group.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
  poll_async:
    description:
      - Poll async jobs until job has finished.
    required: false
    default: true
'''

EXAMPLES = '''
---
# Create a affinity group
- local_action:
    module: cs_affinitygroup
    name: haproxy
    affinty_type: host anti-affinity


# Remove a affinity group
- local_action:
    module: cs_affinitygroup
    name: haproxy
    state: absent
'''

RETURN = '''
---
name:
  description: Name of affinity group.
  returned: success
  type: string
  sample: app
description:
  description: Description of affinity group.
  returned: success
  type: string
  sample: application affinity group
affinity_type:
  description: Type of affinity group.
  returned: success
  type: string
  sample: host anti-affinity
'''

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

class AnsibleCloudStack:

    def __init__(self, module):
        if not has_lib_cs:
            module.fail_json(msg="python library cs required: pip install cs")

        self.module = module
        self._connect()

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

        if api_key and api_secret and api_url:
            self.cs = CloudStack(
                endpoint=api_url,
                key=api_key,
                secret=api_secret,
                method=api_http_method
                )
        else:
            self.cs = CloudStack(**read_config())


    def _has_changed(self, want_dict, current_dict, only_keys=None):
        for key, value in want_dict.iteritems():

            # Optionally limit by a list of keys
            if only_keys and key not in only_keys:
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


    # TODO: for backward compatibility only, remove if not used anymore
    def get_project_id(self):
        return self.get_project(key='id')


    def get_project(self, key=None):
        if self.project:
            return self._get_by_key(key, self.project)

        project = self.module.params.get('project')
        if not project:
            return None

        projects = self.cs.listProjects(listall=True)
        if projects:
            for p in projects['project']:
                if project in [ p['name'], p['displaytext'], p['id'] ]:
                    self.project = p
                    return self._get_by_key(key, self.project)
        self.module.fail_json(msg="project '%s' not found" % project)


    # TODO: for backward compatibility only, remove if not used anymore
    def get_ip_address_id(self):
        return self.get_ip_address(key='id')


    def get_ip_address(self, key=None):
        if self.ip_address:
            return self._get_by_key(key, self.ip_address)

        ip_address = self.module.params.get('ip_address')
        if not ip_address:
            self.module.fail_json(msg="IP address param 'ip_address' is required")

        args = {}
        args['ipaddress'] = ip_address
        args['projectid'] = self.get_project(key='id')
        ip_addresses = self.cs.listPublicIpAddresses(**args)

        if not ip_addresses:
            self.module.fail_json(msg="IP address '%s' not found" % args['ipaddress'])

        self.ip_address = ip_addresses['publicipaddress'][0]
        return self._get_by_key(key, self.ip_address)


    # TODO: for backward compatibility only, remove if not used anymore
    def get_vm_id(self):
        return self.get_vm(key='id')


    def get_vm(self, key=None):
        if self.vm:
            return self._get_by_key(key, self.vm)

        vm = self.module.params.get('vm')
        if not vm:
            self.module.fail_json(msg="Virtual machine param 'vm' is required")

        args = {}
        args['projectid'] = self.get_project(key='id')
        args['zoneid'] = self.get_zone(key='id')
        vms = self.cs.listVirtualMachines(**args)
        if vms:
            for v in vms['virtualmachine']:
                if vm in [ v['name'], v['displayname'], v['id'] ]:
                    self.vm = v
                    return self._get_by_key(key, self.vm)
        self.module.fail_json(msg="Virtual machine '%s' not found" % vm)


    # TODO: for backward compatibility only, remove if not used anymore
    def get_zone_id(self):
        return self.get_zone(key='id')


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


    # TODO: for backward compatibility only, remove if not used anymore
    def get_os_type_id(self):
        return self.get_os_type(key='id')


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


    def get_capabilities(self, key=None):
        if self.capabilities:
            return self._get_by_key(key, self.capabilities)
        capabilities = self.cs.listCapabilities()
        self.capabilities = capabilities['capability']
        return self._get_by_key(key, self.capabilities)


    def _poll_job(self, job=None, key=None):
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


class AnsibleCloudStackAffinityGroup(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)
        self.result = {
            'changed': False,
        }
        self.affinity_group = None


    def get_affinity_group(self):
        if not self.affinity_group:
            affinity_group_name = self.module.params.get('name')

            affinity_groups = self.cs.listAffinityGroups()
            if affinity_groups:
                for a in affinity_groups['affinitygroup']:
                    if a['name'] == affinity_group_name:
                        self.affinity_group = a
                        break
        return self.affinity_group


    def get_affinity_type(self):
        affinity_type = self.module.params.get('affinty_type')

        affinity_types = self.cs.listAffinityGroupTypes()
        if affinity_types:
            if not affinity_type:
                return affinity_types['affinityGroupType'][0]['type']

            for a in affinity_types['affinityGroupType']:
                if a['type'] == affinity_type:
                    return a['type']
        self.module.fail_json(msg="affinity group type '%s' not found" % affinity_type)


    def create_affinity_group(self):
        affinity_group = self.get_affinity_group()
        if not affinity_group:
            self.result['changed'] = True

            args = {}
            args['name'] = self.module.params.get('name')
            args['type'] = self.get_affinity_type()
            args['description'] = self.module.params.get('description')

            if not self.module.check_mode:
                res = self.cs.createAffinityGroup(**args)

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                poll_async = self.module.params.get('poll_async')
                if res and poll_async:
                    affinity_group = self._poll_job(res, 'affinitygroup')

        return affinity_group


    def remove_affinity_group(self):
        affinity_group = self.get_affinity_group()
        if affinity_group:
            self.result['changed'] = True

            args = {}
            args['name'] = self.module.params.get('name')

            if not self.module.check_mode:
                res = self.cs.deleteAffinityGroup(**args)

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                poll_async = self.module.params.get('poll_async')
                if res and poll_async:
                    res = self._poll_job(res, 'affinitygroup')

        return affinity_group


    def get_result(self, affinity_group):
        if affinity_group:
            if 'name' in affinity_group:
                self.result['name'] = affinity_group['name']
            if 'description' in affinity_group:
                self.result['description'] = affinity_group['description']
            if 'type' in affinity_group:
                self.result['affinity_type'] = affinity_group['type']
        return self.result


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True),
            affinty_type = dict(default=None),
            description = dict(default=None),
            state = dict(choices=['present', 'absent'], default='present'),
            poll_async = dict(choices=BOOLEANS, default=True),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
        ),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_ag = AnsibleCloudStackAffinityGroup(module)

        state = module.params.get('state')
        if state in ['absent']:
            affinity_group = acs_ag.remove_affinity_group()
        else:
            affinity_group = acs_ag.create_affinity_group()

        result = acs_ag.get_result(affinity_group)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
