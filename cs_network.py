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
module: cs_network
short_description: Manages networks on Apache CloudStack based clouds.
description:
    - Create, update, restart and delete networks.
version_added: '2.0'
author: "René Moser (@resmo)"
options:
  name:
    description:
      - Name (case sensitive) of the network.
    required: true
  display_text:
    description:
      - Display text of the network.
      - If not specified, C(name) will be used as C(display_text).
    required: false
    default: null
  network_offering:
    description:
      - Name of the offering for the network.
      - Required if C(state=present).
    required: false
    default: null
  start_ip:
    description:
      - The beginning IPv4 address of the network belongs to.
      - Only considered on create.
    required: false
    default: null
  end_ip:
    description:
      - The ending IPv4 address of the network belongs to.
      - If not specified, value of C(start_ip) is used.
      - Only considered on create.
    required: false
    default: null
  gateway:
    description:
      - The gateway of the network.
      - Required for shared networks and isolated networks when it belongs to VPC.
      - Only considered on create.
    required: false
    default: null
  netmask:
    description:
      - The netmask of the network.
      - Required for shared networks and isolated networks when it belongs to VPC.
      - Only considered on create.
    required: false
    default: null
  start_ipv6:
    description:
      - The beginning IPv6 address of the network belongs to.
      - Only considered on create.
    required: false
    default: null
  end_ipv6:
    description:
      - The ending IPv6 address of the network belongs to.
      - If not specified, value of C(start_ipv6) is used.
      - Only considered on create.
    required: false
    default: null
  cidr_ipv6:
    description:
      - CIDR of IPv6 network, must be at least /64.
      - Only considered on create.
    required: false
    default: null
  gateway_ipv6:
    description:
      - The gateway of the IPv6 network. 
      - Required for shared networks.
      - Only considered on create.
    required: false
    default: null
  vlan:
    description:
      - The ID or VID of the network.
    required: false
    default: null
  vpc:
    description:
      - The ID or VID of the network.
    required: false
    default: null
  isolated_pvlan:
    description:
      - The isolated private vlan for this network.
    required: false
    default: null
  clean_up:
    description:
      - Cleanup old network elements.
      - Only considered on C(state=restarted).
    required: false
    default: false
  acl_type:
    description:
      - Access control type.
      - Only considered on create.
    required: false
    default: account
    choices: [ 'account', 'domain' ]
  network_domain:
    description:
      - The network domain.
    required: false
    default: null
  state:
    description:
      - State of the network.
    required: false
    default: present
    choices: [ 'present', 'absent', 'restarted' ]
  zone:
    description:
      - Name of the zone in which the network should be deployed.
      - If not set, default zone is used.
    required: false
    default: null
  project:
    description:
      - Name of the project the network to be deployed in.
    required: false
    default: null
  domain:
    description:
      - Domain the network is related to.
    required: false
    default: null
  account:
    description:
      - Account the network is related to.
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
# create a network
- local_action:
    module: cs_network
    name: my network
    zone: gva-01
    network_offering: DefaultIsolatedNetworkOfferingWithSourceNatService
    network_domain: example.com

# update a network
- local_action:
    module: cs_network
    name: my network
    display_text: network of domain example.local
    network_domain: example.local

# restart a network with clean up
- local_action:
    module: cs_network
    name: my network
    clean_up: yes
    state: restared

# remove a network
- local_action:
    module: cs_network
    name: my network
    state: absent
'''

RETURN = '''
---
id:
  description: UUID of the network.
  returned: success
  type: string
  sample: 04589590-ac63-4ffc-93f5-b698b8ac38b6
name:
  description: Name of the network.
  returned: success
  type: string
  sample: web project
display_text:
  description: Display text of the network.
  returned: success
  type: string
  sample: web project
dns1:
  description: IP address of the 1st nameserver.
  returned: success
  type: string
  sample: 1.2.3.4
dns2:
  description: IP address of the 2nd nameserver.
  returned: success
  type: string
  sample: 1.2.3.4
cidr:
  description: IPv4 network CIDR.
  returned: success
  type: string
  sample: 10.101.64.0/24
gateway:
  description: IPv4 gateway.
  returned: success
  type: string
  sample: 10.101.64.1
netmask:
  description: IPv4 netmask.
  returned: success
  type: string
  sample: 255.255.255.0
cidr_ipv6:
  description: IPv6 network CIDR.
  returned: success
  type: string
  sample: 2001:db8::/64
gateway_ipv6:
  description: IPv6 gateway.
  returned: success
  type: string
  sample: 2001:db8::1
state:
  description: State of the network.
  returned: success
  type: string
  sample: Implemented
zone:
  description: Name of zone.
  returned: success
  type: string
  sample: ch-gva-2
domain:
  description: Domain the network is related to.
  returned: success
  type: string
  sample: ROOT
account:
  description: Account the network is related to.
  returned: success
  type: string
  sample: example account
project:
  description: Name of project.
  returned: success
  type: string
  sample: Production
tags:
  description: List of resource tags associated with the network.
  returned: success
  type: dict
  sample: '[ { "key": "foo", "value": "bar" } ]'
acl_type:
  description: Access type of the network (Domain, Account).
  returned: success
  type: string
  sample: Account
broadcast_domain_type:
  description: Broadcast domain type of the network.
  returned: success
  type: string
  sample: Vlan
type:
  description: Type of the network.
  returned: success
  type: string
  sample: Isolated
traffic_type:
  description: Traffic type of the network.
  returned: success
  type: string
  sample: Guest
state:
  description: State of the network (Allocated, Implemented, Setup).
  returned: success
  type: string
  sample: Allocated
is_persistent:
  description: Whether the network is persistent or not.
  returned: success
  type: boolean
  sample: false
network_domain:
  description: The network domain
  returned: success
  type: string
  sample: example.local
network_offering:
  description: The network offering name.
  returned: success
  type: string
  sample: DefaultIsolatedNetworkOfferingWithSourceNatService
'''

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

# import cloudstack common
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
                if isinstance(value, int):
                    current_dict[key] = int(current_dict[key])
                elif isinstance(value, str):
                    current_dict[key] = str(current_dict[key])

                # Only need to detect a singe change, not every item
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


class AnsibleCloudStackNetwork(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackNetwork, self).__init__(module)
        self.returns = {
            'networkdomain':        'network domain',
            'networkofferingname':  'network_offering',
            'ispersistent':         'is_persistent',
            'acltype':              'acl_type',
            'type':                 'type',
            'traffictype':          'traffic_type',
            'ip6gateway':           'gateway_ipv6',
            'ip6cidr':              'cidr_ipv6',
            'gateway':              'gateway',
            'cidr':                 'cidr',
            'netmask':              'netmask',
            'broadcastdomaintype':  'broadcast_domain_type',
            'dns1':                 'dns1',
            'dns2':                 'dns2',
        }

        self.network = None


    def get_vpc(self, key=None):
        vpc = self.module.params.get('vpc')
        if not vpc:
            return None

        args                = {}
        args['account']     = self.get_account(key='name')
        args['domainid']    = self.get_domain(key='id')
        args['projectid']   = self.get_project(key='id')
        args['zoneid']      = self.get_zone(key='id')

        vpcs = self.cs.listVPCs(**args)
        if vpcs:
            for v in vpcs['vpc']:
                if vpc in [ v['name'], v['displaytext'], v['id'] ]:
                    return self._get_by_key(key, v)
        self.module.fail_json(msg="VPC '%s' not found" % vpc)


    def get_network_offering(self, key=None):
        network_offering = self.module.params.get('network_offering')
        if not network_offering:
            self.module.fail_json(msg="missing required arguments: network_offering")

        args            = {}
        args['zoneid']  = self.get_zone(key='id')

        network_offerings = self.cs.listNetworkOfferings(**args)
        if network_offerings:
            for no in network_offerings['networkoffering']:
                if network_offering in [ no['name'], no['displaytext'], no['id'] ]:
                    return self._get_by_key(key, no)
        self.module.fail_json(msg="Network offering '%s' not found" % network_offering)


    def _get_args(self):
        args                        = {}
        args['name']                = self.module.params.get('name')
        args['displaytext']         = self.get_or_fallback('display_text', 'name')
        args['networkdomain']       = self.module.params.get('network_domain')
        args['networkofferingid']   = self.get_network_offering(key='id')
        return args


    def get_network(self):
        if not self.network:
            network = self.module.params.get('name')

            args                = {}
            args['zoneid']      = self.get_zone(key='id')
            args['projectid']   = self.get_project(key='id')
            args['account']     = self.get_account(key='name')
            args['domainid']    = self.get_domain(key='id')

            networks = self.cs.listNetworks(**args)
            if networks:
                for n in networks['network']:
                    if network in [ n['name'], n['displaytext'], n['id']]:
                        self.network = n
                        break
        return self.network


    def present_network(self):
        network = self.get_network()
        if not network:
            network = self.create_network(network)
        else:
            network = self.update_network(network)
        return network


    def update_network(self, network):
        args        = self._get_args()
        args['id']  = network['id']

        if self.has_changed(args, network):
            self.result['changed'] = True
            if not self.module.check_mode:
                network = self.cs.updateNetwork(**args)

                if 'errortext' in network:
                    self.module.fail_json(msg="Failed: '%s'" % network['errortext'])

                poll_async = self.module.params.get('poll_async')
                if network and poll_async:
                    network = self.poll_job(network, 'network')
        return network


    def create_network(self, network):
        self.result['changed'] = True

        args                    = self._get_args()
        args['acltype']         = self.module.params.get('acl_type')
        args['zoneid']          = self.get_zone(key='id')
        args['projectid']       = self.get_project(key='id')
        args['account']         = self.get_account(key='name')
        args['domainid']        = self.get_domain(key='id')
        args['startip']         = self.module.params.get('start_ip')
        args['endip']           = self.get_or_fallback('end_ip', 'start_ip')
        args['netmask']         = self.module.params.get('netmask')
        args['gateway']         = self.module.params.get('gateway')
        args['startipv6']       = self.module.params.get('start_ipv6')
        args['endipv6']         = self.get_or_fallback('end_ipv6', 'start_ipv6')
        args['ip6cidr']         = self.module.params.get('cidr_ipv6')
        args['ip6gateway']      = self.module.params.get('gateway_ipv6')
        args['vlan']            = self.module.params.get('vlan')
        args['isolatedpvlan']   = self.module.params.get('isolated_pvlan')
        args['subdomainaccess'] = self.module.params.get('subdomain_access')
        args['vpcid']           = self.get_vpc(key='id')

        if not self.module.check_mode:
            res = self.cs.createNetwork(**args)

            if 'errortext' in res:
                self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

            network = res['network']
        return network


    def restart_network(self):
        network = self.get_network()

        if not network:
            self.module.fail_json(msg="No network named '%s' found." % self.module.params('name'))

        # Restarting only available for these states
        if network['state'].lower() in [ 'implemented', 'setup' ]:
            self.result['changed'] = True

            args            = {}
            args['id']      = network['id']
            args['cleanup'] = self.module.params.get('clean_up')

            if not self.module.check_mode:
                network = self.cs.restartNetwork(**args)

                if 'errortext' in network:
                    self.module.fail_json(msg="Failed: '%s'" % network['errortext'])

                poll_async = self.module.params.get('poll_async')
                if network and poll_async:
                    network = self.poll_job(network, 'network')
        return network


    def absent_network(self):
        network = self.get_network()
        if network:
            self.result['changed'] = True

            args        = {}
            args['id']  = network['id']

            if not self.module.check_mode:
                res = self.cs.deleteNetwork(**args)

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                poll_async = self.module.params.get('poll_async')
                if res and poll_async:
                    res = self.poll_job(res, 'network')
            return network



def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        name = dict(required=True),
        display_text = dict(default=None),
        network_offering = dict(default=None),
        zone = dict(default=None),
        start_ip = dict(default=None),
        end_ip = dict(default=None),
        gateway = dict(default=None),
        netmask = dict(default=None),
        start_ipv6 = dict(default=None),
        end_ipv6 = dict(default=None),
        cidr_ipv6 = dict(default=None),
        gateway_ipv6 = dict(default=None),
        vlan = dict(default=None),
        vpc = dict(default=None),
        isolated_pvlan = dict(default=None),
        clean_up = dict(type='bool', default=False),
        network_domain = dict(default=None),
        state = dict(choices=['present', 'absent', 'restarted' ], default='present'),
        acl_type = dict(choices=['account', 'domain'], default='account'),
        project = dict(default=None),
        domain = dict(default=None),
        account = dict(default=None),
        poll_async = dict(type='bool', default=True),
    ))
    required_together = cs_required_together()
    required_together.extend([
        ['start_ip', 'netmask', 'gateway'],
        ['start_ipv6', 'cidr_ipv6', 'gateway_ipv6'],
    ])

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=required_together,
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_network = AnsibleCloudStackNetwork(module)

        state = module.params.get('state')
        if state in ['absent']:
            network = acs_network.absent_network()

        elif state in ['restarted']:
            network = acs_network.restart_network()

        else:
            network = acs_network.present_network()

        result = acs_network.get_result(network)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
