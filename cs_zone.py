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
module: cs_zone
short_description: Manages zones on Apache CloudStack based clouds.
description:
    - Create, update and remove zones.
version_added: "2.1"
author: "René Moser (@resmo)"
options:
  name:
    description:
      - Name of the zone.
    required: true
  id:
    description:
      - uuid of the exising zone.
    default: null
    required: false
  state:
    description:
      - State of the zone.
    required: false
    default: 'present'
    choices: [ 'present', 'enabled', 'disabled', 'absent' ]
  domain:
    description:
      - Domain the zone is related to.
      - Zone is a public zone if not set.
    required: false
    default: null
  network_domain:
    description:
      - Network domain for the zone.
    required: false
    default: null
  network_type:
    description:
      - Network type of the zone.
    required: false
    default: basic
    choices: [ 'basic', 'advanced' ]
  dns1:
    description:
      - First DNS for the zone.
      - Required if C(state=present)
    required: false
    default: null
  dns2:
    description:
      - Second DNS for the zone.
    required: false
    default: null
  internal_dns1:
    description:
      - First internal DNS for the zone.
      - If not set C(dns1) will be used on C(state=present).
    required: false
    default: null
  internal_dns2:
    description:
      - Second internal DNS for the zone.
    required: false
    default: null
  dns1_ipv6:
    description:
      - First DNS for IPv6 for the zone.
    required: false
    default: null
  dns2_ipv6:
    description:
      - Second DNS for IPv6 for the zone.
    required: false
    default: null
  guest_cidr_address:
    description:
      - Guest CIDR address for the zone.
    required: false
    default: null
  dhcp_provider:
    description:
      - DHCP provider for the Zone.
    required: false
    default: null
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
# Ensure a zone is present
- local_action:
    module: cs_zone
    name: ch-zrh-ix-01
    dns1: 8.8.8.8
    dns2: 8.8.4.4
    network_type: basic

# Ensure a zone is disabled
- local_action:
    module: cs_zone
    name: ch-zrh-ix-01
    state: disabled

# Ensure a zone is enabled
- local_action:
    module: cs_zone
    name: ch-zrh-ix-01
    state: enabled

# Ensure a zone is absent
- local_action:
    module: cs_zone
    name: ch-zrh-ix-01
    state: absent
'''

RETURN = '''
---
id:
  description: UUID of the zone.
  returned: success
  type: string
  sample: 04589590-ac63-4ffc-93f5-b698b8ac38b6
name:
  description: Name of the zone.
  returned: success
  type: string
  sample: zone01
dns1:
  description: First DNS for the zone.
  returned: success
  type: string
  sample: 8.8.8.8
dns2:
  description: Second DNS for the zone.
  returned: success
  type: string
  sample: 8.8.4.4
internal_dns1:
  description: First internal DNS for the zone.
  returned: success
  type: string
  sample: 8.8.8.8
internal_dns2:
  description: Second internal DNS for the zone.
  returned: success
  type: string
  sample: 8.8.4.4
dns1_ipv6:
  description: First IPv6 DNS for the zone.
  returned: success
  type: string
  sample: "2001:4860:4860::8888"
dns2_ipv6:
  description: Second IPv6 DNS for the zone.
  returned: success
  type: string
  sample: "2001:4860:4860::8844"
allocation_state:
  description: State of the zone.
  returned: success
  type: string
  sample: Enabled
domain:
  description: Domain the zone is related to.
  returned: success
  type: string
  sample: ROOT
network_domain:
  description: Network domain for the zone.
  returned: success
  type: string
  sample: example.com
network_type:
  description: Network type for the zone.
  returned: success
  type: string
  sample: basic
local_storage_enabled:
  description: Local storage offering enabled.
  returned: success
  type: bool
  sample: false
securitygroups_enabled:
  description: Security groups support is enabled.
  returned: success
  type: bool
  sample: false
guest_cidr_address:
  description: Guest CIDR address for the zone
  returned: success
  type: string
  sample: 10.1.1.0/24
dhcp_provider:
  description: DHCP provider for the zone
  returned: success
  type: string
  sample: VirtualRouter
zone_token:
  description: Zone token
  returned: success
  type: string
  sample: ccb0a60c-79c8-3230-ab8b-8bdbe8c45bb7
tags:
  description: List of resource tags associated with the zone.
  returned: success
  type: dict
  sample: [ { "key": "foo", "value": "bar" } ]
'''

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

# import cloudstack common
CS_HYPERVISORS=[
    'KVM', 'kvm',
    'VMware', 'vmware',
    'BareMetal', 'baremetal',
    'XenServer', 'xenserver',
    'LXC', 'lxc',
    'HyperV', 'hyperv',
    'UCS', 'ucs',
    'OVM', 'ovm',
    'Simulator', 'simulator',
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
        self.tags = None


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
                # API returns string for int in some cases, just to make sure
                if isinstance(value, (int, long, float, complex)):
                    current_dict[key] = int(current_dict[key])
                    if value != current_dict[key]:
                        return True
                elif isinstance(value, str):
                    current_dict[key] = str(current_dict[key])
                    # Test for diff in case insensitive way
                    if value.lower() != current_dict[key].lower():
                        return True
                else:
                    current_dict[key] = str(current_dict[key])
                    if value != current_dict[key]:
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
        zones = self.cs.listZones(name=zone)

        # use the first zone if no zone param given
        if zones:
            self.zone = zones['zone'][0]
            return self._get_by_key(key, self.zone)
        self.module.fail_json(msg="No zones found")


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
        if not self.tags:
            args = {}
            args['projectid'] = self.get_project(key='id')
            args['account'] = self.get_account(key='name')
            args['domainid'] = self.get_domain(key='id')
            args['resourceid'] = resource['id']
            response = self.cs.listTags(**args)
            self.tags = response.get('tag', [])

        existing_tags = []
        if self.tags:
            for tag in self.tags:
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
                self.tags = None
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

class AnsibleCloudStackZone(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackZone, self).__init__(module)
        self.returns = {
            'dns1':                     'dns1',
            'dns2':                     'dns2',
            'internaldns1':             'internal_dns1',
            'internaldns2':             'internal_dns2',
            'ipv6dns1':                 'dns1_ipv6',
            'ipv6dns2':                 'dns2_ipv6',
            'domain':                   'network_domain',
            'networktype':              'network_type',
            'securitygroupsenabled':    'securitygroups_enabled',
            'localstorageenabled':      'local_storage_enabled',
            'guestcidraddress':         'guest_cidr_address',
            'dhcpprovider':             'dhcp_provider',
            'allocationstate':          'allocation_state',
            'zonetoken':                'zone_token',
        }
        self.zone = None


    def _get_common_zone_args(self):
        args = {}
        args['name'] = self.module.params.get('name')
        args['dns1'] = self.module.params.get('dns1')
        args['dns2'] = self.module.params.get('dns2')
        args['internaldns1'] = self.get_or_fallback('internal_dns1', 'dns1')
        args['internaldns2'] = self.get_or_fallback('internal_dns2', 'dns2')
        args['ipv6dns1'] = self.module.params.get('dns1_ipv6')
        args['ipv6dns2'] = self.module.params.get('dns2_ipv6')
        args['networktype'] = self.module.params.get('network_type')
        args['domain'] = self.module.params.get('network_domain')
        args['localstorageenabled'] = self.module.params.get('local_storage_enabled')
        args['guestcidraddress'] = self.module.params.get('guest_cidr_address')
        args['dhcpprovider'] = self.module.params.get('dhcp_provider')
        state = self.module.params.get('state')
        if state in [ 'enabled', 'disabled']:
            args['allocationstate'] = state.capitalize()
        return args


    def get_zone(self):
        if not self.zone:
            args = {}

            uuid = self.module.params.get('id')
            if uuid:
                args['id'] = uuid
                zones = self.cs.listZones(**args)
                if zones:
                    self.zone = zones['zone'][0]
                    return self.zone

            args['name'] = self.module.params.get('name')
            zones = self.cs.listZones(**args)
            if zones:
                self.zone = zones['zone'][0]
        return self.zone


    def present_zone(self):
        zone = self.get_zone()
        if zone:
            zone = self._update_zone()
        else:
            zone = self._create_zone()
        return zone


    def _create_zone(self):
        required_params = [
            'dns1',
        ]
        self.fail_on_missing_params(required_params=required_params)

        self.result['changed'] = True

        args = self._get_common_zone_args()
        args['domainid'] = self.get_domain(key='id')
        args['securitygroupenabled'] = self.module.params.get('securitygroups_enabled')

        zone = None
        if not self.module.check_mode:
            res = self.cs.createZone(**args)
            if 'errortext' in res:
                self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
            zone = res['zone']
        return zone


    def _update_zone(self):
        zone = self.get_zone()

        args = self._get_common_zone_args()
        args['id'] = zone['id']

        if self.has_changed(args, zone):
            self.result['changed'] = True

            if not self.module.check_mode:
                res = self.cs.updateZone(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                zone = res['zone']
        return zone


    def absent_zone(self):
        zone = self.get_zone()
        if zone:
            self.result['changed'] = True

            args = {}
            args['id'] = zone['id']

            if not self.module.check_mode:
                res = self.cs.deleteZone(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
        return zone


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        id = dict(default=None),
        name = dict(required=True),
        dns1 = dict(default=None),
        dns2 = dict(default=None),
        internal_dns1 = dict(default=None),
        internal_dns2 = dict(default=None),
        dns1_ipv6 = dict(default=None),
        dns2_ipv6 = dict(default=None),
        network_type = dict(default='basic', choices=['Basic', 'basic', 'Advanced', 'advanced']),
        network_domain = dict(default=None),
        guest_cidr_address = dict(default=None),
        dhcp_provider = dict(default=None),
        local_storage_enabled = dict(default=None),
        securitygroups_enabled = dict(default=None),
        state = dict(choices=['present', 'enabled', 'disabled', 'absent'], default='present'),
        domain = dict(default=None),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=cs_required_together(),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_zone = AnsibleCloudStackZone(module)

        state = module.params.get('state')
        if state in ['absent']:
            zone = acs_zone.absent_zone()
        else:
            zone = acs_zone.present_zone()

        result = acs_zone.get_result(zone)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
