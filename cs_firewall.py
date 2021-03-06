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
module: cs_firewall
short_description: Manages firewall rules on Apache CloudStack based clouds.
description:
    - Creates and removes firewall rules.
version_added: '2.0'
author: "René Moser (@resmo)"
options:
  ip_address:
    description:
      - Public IP address the ingress rule is assigned to.
      - Required if C(type=ingress).
    required: false
    default: null
  network:
    description:
      - Network the egress rule is related to.
      - Required if C(type=egress).
    required: false
    default: null
  state:
    description:
      - State of the firewall rule.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
  type:
    description:
      - Type of the firewall rule.
    required: false
    default: 'ingress'
    choices: [ 'ingress', 'egress' ]
  protocol:
    description:
      - Protocol of the firewall rule.
      - C(all) is only available if C(type=egress)
    required: false
    default: 'tcp'
    choices: [ 'tcp', 'udp', 'icmp', 'all' ]
  cidr:
    description:
      - CIDR (full notation) to be used for firewall rule.
    required: false
    default: '0.0.0.0/0'
  start_port:
    description:
      - Start port for this rule. Considered if C(protocol=tcp) or C(protocol=udp).
    required: false
    default: null
    aliases: [ 'port' ]
  end_port:
    description:
      - End port for this rule. Considered if C(protocol=tcp) or C(protocol=udp). If not specified, equal C(start_port).
    required: false
    default: null
  icmp_type:
    description:
      - Type of the icmp message being sent. Considered if C(protocol=icmp).
    required: false
    default: null
  icmp_code:
    description:
      - Error code for this icmp message. Considered if C(protocol=icmp).
    required: false
    default: null
  domain:
    description:
      - Domain the firewall rule is related to.
    required: false
    default: null
  account:
    description:
      - Account the firewall rule is related to.
    required: false
    default: null
  project:
    description:
      - Name of the project the firewall rule is related to.
    required: false
    default: null
  zone:
    description:
      - Name of the zone in which the virtual machine is in.
      - If not set, default zone is used.
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
# Allow inbound port 80/tcp from 1.2.3.4 to 4.3.2.1
- local_action:
    module: cs_firewall
    ip_address: 4.3.2.1
    port: 80
    cidr: 1.2.3.4/32

# Allow inbound tcp/udp port 53 to 4.3.2.1
- local_action:
    module: cs_firewall
    ip_address: 4.3.2.1
    port: 53
    protocol: '{{ item }}'
  with_items:
  - tcp
  - udp

# Ensure firewall rule is removed
- local_action:
    module: cs_firewall
    ip_address: 4.3.2.1
    start_port: 8000
    end_port: 8888
    cidr: 17.0.0.0/8
    state: absent

# Allow all outbound traffic
- local_action:
    module: cs_firewall
    network: my_network
    type: egress
    protocol: all

# Allow only HTTP outbound traffic for an IP
- local_action:
    module: cs_firewall
    network: my_network
    type: egress
    port: 80
    cidr: 10.101.1.20
'''

RETURN = '''
---
id:
  description: UUID of the rule.
  returned: success
  type: string
  sample: 04589590-ac63-4ffc-93f5-b698b8ac38b6
ip_address:
  description: IP address of the rule if C(type=ingress)
  returned: success
  type: string
  sample: 10.100.212.10
type:
  description: Type of the rule.
  returned: success
  type: string
  sample: ingress
cidr:
  description: CIDR of the rule.
  returned: success
  type: string
  sample: 0.0.0.0/0
protocol:
  description: Protocol of the rule.
  returned: success
  type: string
  sample: tcp
start_port:
  description: Start port of the rule.
  returned: success
  type: int
  sample: 80
end_port:
  description: End port of the rule.
  returned: success
  type: int
  sample: 80
icmp_code:
  description: ICMP code of the rule.
  returned: success
  type: int
  sample: 1
icmp_type:
  description: ICMP type of the rule.
  returned: success
  type: int
  sample: 1
network:
  description: Name of the network if C(type=egress)
  returned: success
  type: string
  sample: my_network
'''

# import cloudstack common
import os
import time
from ansible.module_utils.six import iteritems

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
            'diff' : {
                'before': dict(),
                'after': dict()
            }
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
            'displaytext',
            'displayname',
            'description',
        ]

        self.module = module
        self._connect()

        # Helper for VPCs
        self._vpc_networks_ids = None

        self.domain = None
        self.account = None
        self.project = None
        self.ip_address = None
        self.network = None
        self.vpc = None
        self.zone = None
        self.vm = None
        self.vm_default_nic = None
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


    # TODO: for backward compatibility only, remove if not used anymore
    def _has_changed(self, want_dict, current_dict, only_keys=None):
        return self.has_changed(want_dict=want_dict, current_dict=current_dict, only_keys=only_keys)


    def has_changed(self, want_dict, current_dict, only_keys=None):
        result = False
        for key, value in want_dict.iteritems():

            # Optionally limit by a list of keys
            if only_keys and key not in only_keys:
                continue

            # Skip None values
            if value is None:
                continue

            if key in current_dict:
                if isinstance(value, (int, float, long, complex)):
                    # ensure we compare the same type
                    if isinstance(value, int):
                        current_dict[key] = int(current_dict[key])
                    elif isinstance(value, float):
                        current_dict[key] = float(current_dict[key])
                    elif isinstance(value, long):
                        current_dict[key] = long(current_dict[key])
                    elif isinstance(value, complex):
                        current_dict[key] = complex(current_dict[key])

                    if value != current_dict[key]:
                        self.result['diff']['before'][key] = current_dict[key]
                        self.result['diff']['after'][key] = value
                        result = True
                else:
                    if self.case_sensitive_keys and key in self.case_sensitive_keys:
                        if value != current_dict[key].encode('utf-8'):
                            self.result['diff']['before'][key] = current_dict[key].encode('utf-8')
                            self.result['diff']['after'][key] = value
                            result = True

                    # Test for diff in case insensitive way
                    elif value.lower() != current_dict[key].encode('utf-8').lower():
                        self.result['diff']['before'][key] = current_dict[key].encode('utf-8')
                        self.result['diff']['after'][key] = value
                        result = True
            else:
                self.result['diff']['before'][key] = None
                self.result['diff']['after'][key] = value
                result = True
        return result


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
            vpc = os.environ.get('CLOUDSTACK_VPC')
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


    def is_vm_in_vpc(self, vm):
        for n in vm.get('nic'):
            if n.get('isdefault', False):
                return self.is_vpc_network(network_id=n['networkid'])
        self.module.fail_json(msg="VM has no default nic")


    def is_vpc_network(self, network_id):
        """Returns True if network is in VPC."""
        # This is an efficient way to query a lot of networks at a time
        if self._vpc_networks_ids is None:
            args = {
                'account': self.get_account(key='name'),
                'domainid': self.get_domain(key='id'),
                'projectid': self.get_project(key='id'),
                'zoneid': self.get_zone(key='id'),
            }
            vpcs = self.cs.listVPCs(**args)
            self._vpc_networks_ids = []
            if vpcs:
                for vpc in vpcs['vpc']:
                    for n in vpc.get('network',[]):
                        self._vpc_networks_ids.append(n['id'])
        return network_id in self._vpc_networks_ids


    def get_network(self, key=None):
        """Return a network dictionary or the value of given key of."""
        if self.network:
            return self._get_by_key(key, self.network)

        network = self.module.params.get('network')
        if not network:
            return None

        args = {
            'account': self.get_account(key='name'),
            'domainid': self.get_domain(key='id'),
            'projectid': self.get_project(key='id'),
            'zoneid': self.get_zone(key='id'),
            'vpcid': self.get_vpc(key='id')
        }
        networks = self.cs.listNetworks(**args)
        if not networks:
            self.module.fail_json(msg="No networks available.")

        for n in networks['network']:
            # ignore any VPC network if vpc param is not given
            if 'vpcid' in n and not self.get_vpc(key='id'):
                continue
            if network in [n['displaytext'], n['name'], n['id']]:
                self.network = n
                return self._get_by_key(key, self.network)
        self.module.fail_json(msg="Network '%s' not found" % network)


    def get_project(self, key=None):
        if self.project:
            return self._get_by_key(key, self.project)

        project = self.module.params.get('project')
        if not project:
            project = os.environ.get('CLOUDSTACK_PROJECT')
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

        args = {
            'ipaddress': ip_address,
            'account': self.get_account(key='name'),
            'domainid': self.get_domain(key='id'),
            'projectid': self.get_project(key='id'),
            'vpcid': self.get_vpc(key='id'),
        }
        ip_addresses = self.cs.listPublicIpAddresses(**args)

        if not ip_addresses:
            self.module.fail_json(msg="IP address '%s' not found" % args['ipaddress'])

        self.ip_address = ip_addresses['publicipaddress'][0]
        return self._get_by_key(key, self.ip_address)


    def get_vm_guest_ip(self):
        vm_guest_ip = self.module.params.get('vm_guest_ip')
        default_nic = self.get_vm_default_nic()

        if not vm_guest_ip:
            return default_nic['ipaddress']

        for secondary_ip in default_nic['secondaryip']:
            if vm_guest_ip == secondary_ip['ipaddress']:
                return vm_guest_ip
        self.module.fail_json(msg="Secondary IP '%s' not assigned to VM" % vm_guest_ip)


    def get_vm_default_nic(self):
        if self.vm_default_nic:
            return self.vm_default_nic

        nics = self.cs.listNics(virtualmachineid=self.get_vm(key='id'))
        if nics:
            for n in nics['nic']:
                if n['isdefault']:
                    self.vm_default_nic = n
                    return self.vm_default_nic
        self.module.fail_json(msg="No default IP address of VM '%s' found" % self.module.params.get('vm'))


    def get_vm(self, key=None):
        if self.vm:
            return self._get_by_key(key, self.vm)

        vm = self.module.params.get('vm')
        if not vm:
            self.module.fail_json(msg="Virtual machine param 'vm' is required")

        vpc_id = self.get_vpc(key='id')

        args = {
            'account': self.get_account(key='name'),
            'domainid': self.get_domain(key='id'),
            'projectid': self.get_project(key='id'),
            'zoneid': self.get_zone(key='id'),
            'vpcid': vpc_id,
        }
        vms = self.cs.listVirtualMachines(**args)
        if vms:
            for v in vms['virtualmachine']:
                # Due the limitation of the API, there is no easy way (yet) to get only those VMs
                # not belonging to a VPC.
                if not vpc_id and self.is_vm_in_vpc(vm=v):
                    continue
                if vm.lower() in [ v['name'].lower(), v['displayname'].lower(), v['id'] ]:
                    self.vm = v
                    return self._get_by_key(key, self.vm)
        self.module.fail_json(msg="Virtual machine '%s' not found" % vm)


    def get_zone(self, key=None):
        if self.zone:
            return self._get_by_key(key, self.zone)

        zone = self.module.params.get('zone')
        if not zone:
            zone = os.environ.get('CLOUDSTACK_ZONE')
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
            account = os.environ.get('CLOUDSTACK_ACCOUNT')
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
            domain = os.environ.get('CLOUDSTACK_DOMAIN')
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


class AnsibleCloudStackFirewall(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackFirewall, self).__init__(module)
        self.returns = {
            'cidrlist':     'cidr',
            'startport':    'start_port',
            'endpoint':     'end_port',
            'protocol':     'protocol',
            'ipaddress':    'ip_address',
            'icmpcode':     'icmp_code',
            'icmptype':     'icmp_type',
        }
        self.firewall_rule = None
        self.network = None


    def get_firewall_rule(self):
        if not self.firewall_rule:
            cidr        = self.module.params.get('cidr')
            protocol    = self.module.params.get('protocol')
            start_port  = self.module.params.get('start_port')
            end_port    = self.get_or_fallback('end_port', 'start_port')
            icmp_code   = self.module.params.get('icmp_code')
            icmp_type   = self.module.params.get('icmp_type')
            fw_type     = self.module.params.get('type')

            if protocol in ['tcp', 'udp'] and not (start_port and end_port):
                self.module.fail_json(msg="missing required argument for protocol '%s': start_port or end_port" % protocol)

            if protocol == 'icmp' and not icmp_type:
                self.module.fail_json(msg="missing required argument for protocol 'icmp': icmp_type")

            if protocol == 'all' and fw_type != 'egress':
                self.module.fail_json(msg="protocol 'all' could only be used for type 'egress'" )

            args                = {}
            args['account']     = self.get_account('name')
            args['domainid']    = self.get_domain('id')
            args['projectid']   = self.get_project('id')

            if fw_type == 'egress':
                args['networkid'] = self.get_network(key='id')
                if not args['networkid']:
                    self.module.fail_json(msg="missing required argument for type egress: network")
                firewall_rules = self.cs.listEgressFirewallRules(**args)
            else:
                args['ipaddressid'] = self.get_ip_address('id')
                if not args['ipaddressid']:
                    self.module.fail_json(msg="missing required argument for type ingress: ip_address")
                firewall_rules = self.cs.listFirewallRules(**args)

            if firewall_rules and 'firewallrule' in firewall_rules:
                for rule in firewall_rules['firewallrule']:
                    type_match = self._type_cidr_match(rule, cidr)

                    protocol_match = self._tcp_udp_match(rule, protocol, start_port, end_port) \
                        or self._icmp_match(rule, protocol, icmp_code, icmp_type) \
                        or self._egress_all_match(rule, protocol, fw_type)

                    if type_match and protocol_match:
                        self.firewall_rule = rule
                        break
        return self.firewall_rule


    def _tcp_udp_match(self, rule, protocol, start_port, end_port):
        return protocol in ['tcp', 'udp'] \
            and protocol == rule['protocol'] \
            and start_port == int(rule['startport']) \
            and end_port == int(rule['endport'])


    def _egress_all_match(self, rule, protocol, fw_type):
        return protocol in ['all'] \
            and protocol == rule['protocol'] \
            and fw_type == 'egress'


    def _icmp_match(self, rule, protocol, icmp_code, icmp_type):
        return protocol == 'icmp' \
           and protocol == rule['protocol'] \
           and icmp_code == rule['icmpcode'] \
           and icmp_type == rule['icmptype']


    def _type_cidr_match(self, rule, cidr):
        return cidr == rule['cidrlist']


    def create_firewall_rule(self):
        firewall_rule = self.get_firewall_rule()
        if not firewall_rule:
            self.result['changed'] = True

            args                = {}
            args['cidrlist']    = self.module.params.get('cidr')
            args['protocol']    = self.module.params.get('protocol')
            args['startport']   = self.module.params.get('start_port')
            args['endport']     = self.get_or_fallback('end_port', 'start_port')
            args['icmptype']    = self.module.params.get('icmp_type')
            args['icmpcode']    = self.module.params.get('icmp_code')

            fw_type = self.module.params.get('type')
            if not self.module.check_mode:
                if fw_type == 'egress':
                    args['networkid'] = self.get_network(key='id')
                    res = self.cs.createEgressFirewallRule(**args)
                else:
                    args['ipaddressid'] = self.get_ip_address('id')
                    res = self.cs.createFirewallRule(**args)

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                     firewall_rule = self.poll_job(res, 'firewallrule')
        return firewall_rule


    def remove_firewall_rule(self):
        firewall_rule = self.get_firewall_rule()
        if firewall_rule:
            self.result['changed'] = True

            args       = {}
            args['id'] = firewall_rule['id']

            fw_type = self.module.params.get('type')
            if not self.module.check_mode:
                if fw_type == 'egress':
                    res = self.cs.deleteEgressFirewallRule(**args)
                else:
                    res = self.cs.deleteFirewallRule(**args)

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                     res = self.poll_job(res, 'firewallrule')
        return firewall_rule


    def get_result(self, firewall_rule):
        super(AnsibleCloudStackFirewall, self).get_result(firewall_rule)
        if firewall_rule:
            self.result['type'] = self.module.params.get('type')
            if self.result['type'] == 'egress':
                self.result['network'] = self.get_network(key='displaytext')
        return self.result


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        ip_address = dict(default=None),
        network = dict(default=None),
        cidr = dict(default='0.0.0.0/0'),
        protocol = dict(choices=['tcp', 'udp', 'icmp', 'all'], default='tcp'),
        type = dict(choices=['ingress', 'egress'], default='ingress'),
        icmp_type = dict(type='int', default=None),
        icmp_code = dict(type='int', default=None),
        start_port = dict(type='int', aliases=['port'], default=None),
        end_port = dict(type='int', default=None),
        state = dict(choices=['present', 'absent'], default='present'),
        zone = dict(default=None),
        domain = dict(default=None),
        account = dict(default=None),
        project = dict(default=None),
        poll_async = dict(type='bool', default=True),
    ))

    required_together = cs_required_together()
    required_together.extend([
        ['icmp_type', 'icmp_code'],
    ])

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=required_together,
        required_one_of = (
            ['ip_address', 'network'],
        ),
        mutually_exclusive = (
            ['icmp_type', 'start_port'],
            ['icmp_type', 'end_port'],
            ['ip_address', 'network'],
        ),
        supports_check_mode=True
    )

    try:
        acs_fw = AnsibleCloudStackFirewall(module)

        state = module.params.get('state')
        if state in ['absent']:
            fw_rule = acs_fw.remove_firewall_rule()
        else:
            fw_rule = acs_fw.create_firewall_rule()

        result = acs_fw.get_result(fw_rule)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
