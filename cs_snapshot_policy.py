#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2016, René Moser <mail@renemoser.net>
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
module: cs_snapshot_policy
short_description: Manages volume snapshot policies on Apache CloudStack based clouds.
description:
    - Create, update and delete volume snapshot policies.
version_added: '2.2'
author: "René Moser (@resmo)"
options:
  volume:
    description:
      - Name of the volume.
    required: true
  interval_type:
    description:
      - Interval of the snapshot.
    required: false
    default: 'daily'
    choices: [ 'hourly', 'daily', 'weekly', 'monthly' ]
    aliases: [ 'interval' ]
  max_snaps:
    description:
      - Max number of snapshots.
    required: false
    default: 8
    aliases: [ 'max' ]
  schedule:
    description:
      - Time the snapshot is scheduled. Required if C(state=present).
      - 'Format for C(interval_type=HOURLY): C(MM)'
      - 'Format for C(interval_type=DAILY): C(MM:HH)'
      - 'Format for C(interval_type=WEEKLY): C(MM:HH:DD (1-7))'
      - 'Format for C(interval_type=MONTHLY): C(MM:HH:DD (1-28))'
    required: false
    default: null
  time_zone:
    description:
      - Specifies a timezone for this command.
    required: false
    default: 'UTC'
    aliases: [ 'timezone' ]
  state:
    description:
      - State of the snapshot policy.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
  domain:
    description:
      - Domain the volume is related to.
    required: false
    default: null
  account:
    description:
      - Account the volume is related to.
    required: false
    default: null
  project:
    description:
      - Name of the project the volume is related to.
    required: false
    default: null
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
# Ensure a snapshot policy daily at 1h00 UTC
- local_action:
    module: cs_snapshot_policy
    volume: ROOT-478
    schedule: '00:1'
    max_snaps: 3

# Ensure a snapshot policy hourly at minute 5 UTC
- local_action:
    module: cs_snapshot_policy
    volume: ROOT-478
    schedule: '5'
    interval_type: hourly
    max_snaps: 1

# Ensure a snapshot policy weekly on Sunday at 05h00, TZ Europe/Zurich
- local_action:
    module: cs_snapshot_policy
    volume: ROOT-478
    schedule: '00:5:1'
    interval_type: weekly
    max_snaps: 1
    time_zone: 'Europe/Zurich'

# Ensure a snapshot policy is absent
- local_action:
    module: cs_snapshot_policy
    volume: ROOT-478
    interval_type: hourly
    state: absent
'''

RETURN = '''
---
id:
  description: UUID of the snapshot policy.
  returned: success
  type: string
  sample: a6f7a5fc-43f8-11e5-a151-feff819cdc9f
interval_type:
  description: interval type of the snapshot policy.
  returned: success
  type: string
  sample: daily
schedule:
  description: schedule of the snapshot policy.
  returned: success
  type: string
  sample:
max_snaps:
  description: maximum number of snapshots retained.
  returned: success
  type: int
  sample: 10
time_zone:
  description: the time zone of the snapshot policy.
  returned: success
  type: string
  sample: Etc/UTC
volume:
  description: the volume of the snapshot policy.
  returned: success
  type: string
  sample: Etc/UTC
zone:
  description: Name of zone the volume is related to.
  returned: success
  type: string
  sample: ch-gva-2
project:
  description: Name of project the volume is related to.
  returned: success
  type: string
  sample: Production
account:
  description: Account the volume is related to.
  returned: success
  type: string
  sample: example account
domain:
  description: Domain the volume is related to.
  returned: success
  type: string
  sample: example domain
'''

# import cloudstack common
import time

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

CS_HYPERVISORS = [
    "KVM", "kvm",
    "VMware", "vmware",
    "BareMetal", "baremetal",
    "XenServer", "xenserver",
    "LXC", "lxc",
    "HyperV", "hyperv",
    "UCS", "ucs",
    "OVM", "ovm",
    "Simulator", "simulator",
    ]

def cs_argument_spec():
    return dict(
        api_key = dict(default=None),
        api_secret = dict(default=None, no_log=True),
        api_url = dict(default=None),
        api_http_method = dict(choices=['get', 'post'], default='get'),
        api_timeout = dict(type='int', default=10),
        api_region = dict(default='cloudstack'),
    )

def cs_required_together():
    return [['api_key', 'api_secret', 'api_url']]

class AnsibleCloudStack(object):

    def __init__(self, module):
        if not has_lib_cs:
            module.fail_json(msg="python library cs required: pip install cs")

        self.result = {
            'changed': False,
        }

        # Common returns, will be merged with self.returns
        # search_for_key: replace_with_key
        self.common_returns = {
            'id':           'id',
            'name':         'name',
            'created':      'created',
            'zonename':     'zone',
            'state':        'state',
            'project':      'project',
            'account':      'account',
            'domain':       'domain',
            'displaytext':  'display_text',
            'displayname':  'display_name',
            'description':  'description',
        }

        # Init returns dict for use in subclasses
        self.returns = {}
        # these values will be casted to int
        self.returns_to_int = {}
        # these keys will be compared case sensitive in self.has_changed()
        self.case_sensitive_keys = [
            'id',
        ]

        self.module = module
        self._connect()

        self.domain = None
        self.account = None
        self.project = None
        self.ip_address = None
        self.network = None
        self.vpc = None
        self.zone = None
        self.vm = None
        self.os_type = None
        self.hypervisor = None
        self.capabilities = None


    def _connect(self):
        api_key = self.module.params.get('api_key')
        api_secret = self.module.params.get('api_secret')
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
            api_region = self.module.params.get('api_region', 'cloudstack')
            self.cs = CloudStack(**read_config(api_region))


    def get_or_fallback(self, key=None, fallback_key=None):
        value = self.module.params.get(key)
        if not value:
            value = self.module.params.get(fallback_key)
        return value


    def fail_on_missing_params(self, required_params=None):
        if not required_params:
            return
        missing_params = []
        for required_param in required_params:
            if not self.module.params.get(required_param):
                missing_params.append(required_param)
        if missing_params:
            self.module.fail_json(msg="missing required arguments: %s" % ','.join(missing_params))


    # TODO: for backward compatibility only, remove if not used anymore
    def _has_changed(self, want_dict, current_dict, only_keys=None):
        return self.has_changed(want_dict=want_dict, current_dict=current_dict, only_keys=only_keys)


    def has_changed(self, want_dict, current_dict, only_keys=None):
        for key, value in want_dict.iteritems():

            # Optionally limit by a list of keys
            if only_keys and key not in only_keys:
                continue

            # Skip None values
            if value is None:
                continue

            if key in current_dict:
                if self.case_sensitive_keys and key in self.case_sensitive_keys:
                    if str(value) != str(current_dict[key]):
                        return True
                # Test for diff in case insensitive way
                elif str(value).lower() != str(current_dict[key]).lower():
                    return True
            else:
                return True
        return False


    def _get_by_key(self, key=None, my_dict=None):
        if my_dict is None:
            my_dict = {}
        if key:
            if key in my_dict:
                return my_dict[key]
            self.module.fail_json(msg="Something went wrong: %s not found" % key)
        return my_dict


    def get_vpc(self, key=None):
        """Return a VPC dictionary or the value of given key of."""
        if self.vpc:
            return self._get_by_key(key, self.vpc)

        vpc = self.module.params.get('vpc')
        if not vpc:
            return None

        args = {
            'account': self.get_account(key='name'),
            'domainid': self.get_domain(key='id'),
            'projectid': self.get_project(key='id'),
            'zoneid': self.get_zone(key='id'),
        }
        vpcs = self.cs.listVPCs(**args)
        if not vpcs:
            self.module.fail_json(msg="No VPCs available.")

        for v in vpcs['vpc']:
            if vpc in [v['displaytext'], v['name'], v['id']]:
                self.vpc = v
                return self._get_by_key(key, self.vpc)
        self.module.fail_json(msg="VPC '%s' not found" % vpc)


    def get_network(self, key=None):
        """Return a network dictionary or the value of given key of."""
        if self.network:
            return self._get_by_key(key, self.network)

        network = self.module.params.get('network')
        if not network:
            return None

        args = {
            'account': self.get_account('name'),
            'domainid': self.get_domain('id'),
            'projectid': self.get_project('id'),
            'zoneid': self.get_zone('id'),
        }
        networks = self.cs.listNetworks(**args)
        if not networks:
            self.module.fail_json(msg="No networks available.")

        for n in networks['network']:
            if network in [n['displaytext'], n['name'], n['id']]:
                self.network = n
                return self._get_by_key(key, self.network)
        self.module.fail_json(msg="Network '%s' not found" % network)


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
                if vm.lower() in [ v['name'].lower(), v['displayname'].lower(), v['id'] ]:
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
                if zone.lower() in [ z['name'].lower(), z['id'] ]:
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
                if d['path'].lower() in [ domain.lower(), "root/" + domain.lower(), "root" + domain.lower() ]:
                    self.domain = d
                    return self._get_by_key(key, self.domain)
        self.module.fail_json(msg="Domain '%s' not found" % domain)


    def get_tags(self, resource=None):
        existing_tags = []
        for tag in resource.get('tags',[]):
            existing_tags.append({'key': tag['key'], 'value': tag['value']})
        return existing_tags


    def _process_tags(self, resource, resource_type, tags, operation="create"):
        if tags:
            self.result['changed'] = True
            if not self.module.check_mode:
                args = {}
                args['resourceids']  = resource['id']
                args['resourcetype'] = resource_type
                args['tags']         = tags
                if operation == "create":
                    response = self.cs.createTags(**args)
                else:
                    response = self.cs.deleteTags(**args)
                self.poll_job(response)


    def _tags_that_should_exist_or_be_updated(self, resource, tags):
        existing_tags = self.get_tags(resource)
        return [tag for tag in tags if tag not in existing_tags]


    def _tags_that_should_not_exist(self, resource, tags):
        existing_tags = self.get_tags(resource)
        return [tag for tag in existing_tags if tag not in tags]


    def ensure_tags(self, resource, resource_type=None):
        if not resource_type or not resource:
            self.module.fail_json(msg="Error: Missing resource or resource_type for tags.")

        if 'tags' in resource:
            tags = self.module.params.get('tags')
            if tags is not None:
                self._process_tags(resource, resource_type, self._tags_that_should_not_exist(resource, tags), operation="delete")
                self._process_tags(resource, resource_type, self._tags_that_should_exist_or_be_updated(resource, tags))
                resource['tags'] = tags
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


    def get_result(self, resource):
        if resource:
            returns = self.common_returns.copy()
            returns.update(self.returns)
            for search_key, return_key in returns.iteritems():
                if search_key in resource:
                    self.result[return_key] = resource[search_key]

            # Bad bad API does not always return int when it should.
            for search_key, return_key in self.returns_to_int.iteritems():
                if search_key in resource:
                    self.result[return_key] = int(resource[search_key])

            # Special handling for tags
            if 'tags' in resource:
                self.result['tags'] = []
                for tag in resource['tags']:
                    result_tag          = {}
                    result_tag['key']   = tag['key']
                    result_tag['value'] = tag['value']
                    self.result['tags'].append(result_tag)
        return self.result


class AnsibleCloudStackSnapshotPolicy(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackSnapshotPolicy, self).__init__(module)
        self.returns = {
            'schedule': 'schedule',
            'timezone': 'time_zone',
            'maxsnaps': 'max_snaps',
        }
        self.interval_types = {
            'hourly':   0,
            'daily':    1,
            'weekly':   2,
            'monthly':  3,
        }
        self.volume = None

    def get_interval_type(self):
        interval_type = self.module.params.get('interval_type')
        return self.interval_types[interval_type]

    def get_volume(self, key=None):
        if self.volume:
            return self._get_by_key(key, self.volume)

        args = {
            'name':         self.module.params.get('volume'),
            'account':      self.get_account(key='name'),
            'domainid':     self.get_domain(key='id'),
            'projectid':    self.get_project(key='id'),
        }
        volumes = self.cs.listVolumes(**args)
        if volumes:
            self.volume = volumes['volume'][0]
            return self._get_by_key(key, self.volume)
        return None

    def get_snapshot_policy(self):
        args = {
            'volumeid': self.get_volume(key='id')
        }
        policies = self.cs.listSnapshotPolicies(**args)
        if policies:
            for policy in policies['snapshotpolicy']:
                if policy['intervaltype'] == self.get_interval_type():
                    return policy
            return None

    def present_snapshot_policy(self):
        required_params = [
            'schedule',
        ]
        self.fail_on_missing_params(required_params=required_params)

        policy = self.get_snapshot_policy()
        args = {
            'intervaltype': self.module.params.get('interval_type'),
            'schedule':     self.module.params.get('schedule'),
            'maxsnaps':     self.module.params.get('max_snaps'),
            'timezone':     self.module.params.get('time_zone'),
            'volumeid':     self.get_volume(key='id')
        }
        if not policy or (policy and self.has_changed(policy, args)):
            self.result['changed'] = True
            if not self.module.check_mode:
                res = self.cs.createSnapshotPolicy(**args)
                policy = res['snapshotpolicy']
                if 'errortext' in policy:
                    self.module.fail_json(msg="Failed: '%s'" % policy['errortext'])
        return policy

    def absent_snapshot_policy(self):
        policy = self.get_snapshot_policy()
        if policy:
            self.result['changed'] = True
            args = {
                'id': policy['id']
            }
            if not self.module.check_mode:
                res = self.cs.deleteSnapshotPolicies(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % policy['errortext'])
        return policy

    def get_result(self, policy):
        super(AnsibleCloudStackSnapshotPolicy, self).get_result(policy)
        if policy and 'intervaltype' in policy:
            for key, value in self.interval_types.items():
                if value == policy['intervaltype']:
                    self.result['interval_type'] = key
                    break
        volume = self.get_volume()
        if volume:
            volume_results = {
                'volume':   volume.get('name'),
                'zone':     volume.get('zonename'),
                'project':  volume.get('project'),
                'account':  volume.get('account'),
                'domain':   volume.get('domain'),
            }
            self.result.update(volume_results)
        return self.result


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        volume=dict(required=True),
        interval_type=dict(default='daily', choices=['hourly', 'daily', 'weekly', 'monthly'], aliases=['interval']),
        schedule=dict(default=None),
        time_zone=dict(default='UTC', aliases=['timezone']),
        max_snaps=dict(type='int', default=8, aliases=['max']),
        state=dict(choices=['present', 'absent'], default='present'),
        domain=dict(default=None),
        account=dict(default=None),
        project=dict(default=None),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=cs_required_together(),
        supports_check_mode=True
    )

    try:
        acs_snapshot_policy = AnsibleCloudStackSnapshotPolicy(module)

        state = module.params.get('state')
        if state in ['absent']:
            policy = acs_snapshot_policy.absent_snapshot_policy()
        else:
            policy = acs_snapshot_policy.present_snapshot_policy()

        result = acs_snapshot_policy.get_result(policy)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()