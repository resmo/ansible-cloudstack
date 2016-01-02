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
module: cs_securitygroup_rule
short_description: Manages security group rules on Apache CloudStack based clouds.
description:
    - Add and remove security group rules.
version_added: '2.0'
author: "René Moser (@resmo)"
options:
  security_group:
    description:
      - Name of the security group the rule is related to. The security group must be existing.
    required: true
  state:
    description:
      - State of the security group rule.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
  protocol:
    description:
      - Protocol of the security group rule.
    required: false
    default: 'tcp'
    choices: [ 'tcp', 'udp', 'icmp', 'ah', 'esp', 'gre' ]
  type:
    description:
      - Ingress or egress security group rule.
    required: false
    default: 'ingress'
    choices: [ 'ingress', 'egress' ]
  cidr:
    description:
      - CIDR (full notation) to be used for security group rule.
    required: false
    default: '0.0.0.0/0'
  user_security_group:
    description:
      - Security group this rule is based of.
    required: false
    default: null
  start_port:
    description:
      - Start port for this rule. Required if C(protocol=tcp) or C(protocol=udp).
    required: false
    default: null
    aliases: [ 'port' ]
  end_port:
    description:
      - End port for this rule. Required if C(protocol=tcp) or C(protocol=udp), but C(start_port) will be used if not set.
    required: false
    default: null
  icmp_type:
    description:
      - Type of the icmp message being sent. Required if C(protocol=icmp).
    required: false
    default: null
  icmp_code:
    description:
      - Error code for this icmp message. Required if C(protocol=icmp).
    required: false
    default: null
  project:
    description:
      - Name of the project the security group to be created in.
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
---
# Allow inbound port 80/tcp from 1.2.3.4 added to security group 'default'
- local_action:
    module: cs_securitygroup_rule
    security_group: default
    port: 80
    cidr: 1.2.3.4/32

# Allow tcp/udp outbound added to security group 'default'
- local_action:
    module: cs_securitygroup_rule
    security_group: default
    type: egress
    start_port: 1
    end_port: 65535
    protocol: '{{ item }}'
  with_items:
  - tcp
  - udp

# Allow inbound icmp from 0.0.0.0/0 added to security group 'default'
- local_action:
    module: cs_securitygroup_rule
    security_group: default
    protocol: icmp
    icmp_code: -1
    icmp_type: -1

# Remove rule inbound port 80/tcp from 0.0.0.0/0 from security group 'default'
- local_action:
    module: cs_securitygroup_rule
    security_group: default
    port: 80
    state: absent

# Allow inbound port 80/tcp from security group web added to security group 'default'
- local_action:
    module: cs_securitygroup_rule
    security_group: default
    port: 80
    user_security_group: web
'''

RETURN = '''
---
id:
  description: UUID of the of the rule.
  returned: success
  type: string
  sample: a6f7a5fc-43f8-11e5-a151-feff819cdc9f
security_group:
  description: security group of the rule.
  returned: success
  type: string
  sample: default
type:
  description: type of the rule.
  returned: success
  type: string
  sample: ingress
cidr:
  description: CIDR of the rule.
  returned: success and cidr is defined
  type: string
  sample: 0.0.0.0/0
user_security_group:
  description: user security group of the rule.
  returned: success and user_security_group is defined
  type: string
  sample: default
protocol:
  description: protocol of the rule.
  returned: success
  type: string
  sample: tcp
start_port:
  description: start port of the rule.
  returned: success
  type: int
  sample: 80
end_port:
  description: end port of the rule.
  returned: success
  type: int
  sample: 80
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


class AnsibleCloudStackSecurityGroupRule(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackSecurityGroupRule, self).__init__(module)
        self.returns = {
            'icmptype':             'icmp_type',
            'icmpcode':             'icmp_code',
            'endport':              'end_port',
            'startport':            'start_port',
            'protocol':             'protocol',
            'cidr':                 'cidr',
            'securitygroupname':    'user_security_group',
        }


    def _tcp_udp_match(self, rule, protocol, start_port, end_port):
        return protocol in ['tcp', 'udp'] \
               and protocol == rule['protocol'] \
               and start_port == int(rule['startport']) \
               and end_port == int(rule['endport'])


    def _icmp_match(self, rule, protocol, icmp_code, icmp_type):
        return protocol == 'icmp' \
               and protocol == rule['protocol'] \
               and icmp_code == int(rule['icmpcode']) \
               and icmp_type == int(rule['icmptype'])


    def _ah_esp_gre_match(self, rule, protocol):
        return protocol in ['ah', 'esp', 'gre'] \
               and protocol == rule['protocol']


    def _type_security_group_match(self, rule, security_group_name):
        return security_group_name \
               and 'securitygroupname' in rule \
               and security_group_name == rule['securitygroupname']


    def _type_cidr_match(self, rule, cidr):
        return 'cidr' in rule \
               and cidr == rule['cidr']


    def _get_rule(self, rules):
        user_security_group_name = self.module.params.get('user_security_group')
        cidr                     = self.module.params.get('cidr')
        protocol                 = self.module.params.get('protocol')
        start_port               = self.module.params.get('start_port')
        end_port                 = self.get_or_fallback('end_port', 'start_port')
        icmp_code                = self.module.params.get('icmp_code')
        icmp_type                = self.module.params.get('icmp_type')

        if protocol in ['tcp', 'udp'] and not (start_port and end_port):
            self.module.fail_json(msg="no start_port or end_port set for protocol '%s'" % protocol)

        if protocol == 'icmp' and not (icmp_type and icmp_code):
            self.module.fail_json(msg="no icmp_type or icmp_code set for protocol '%s'" % protocol)

        for rule in rules:
            if user_security_group_name:
                type_match = self._type_security_group_match(rule, user_security_group_name)
            else:
                type_match = self._type_cidr_match(rule, cidr)

            protocol_match = (    self._tcp_udp_match(rule, protocol, start_port, end_port) \
                               or self._icmp_match(rule, protocol, icmp_code, icmp_type) \
                               or self._ah_esp_gre_match(rule, protocol)
                             )

            if type_match and protocol_match:
                return rule
        return None


    def get_security_group(self, security_group_name=None):
        if not security_group_name:
            security_group_name = self.module.params.get('security_group')
        args = {}
        args['securitygroupname'] =  security_group_name
        args['projectid'] = self.get_project('id')
        sgs = self.cs.listSecurityGroups(**args)
        if not sgs or 'securitygroup' not in sgs:
                self.module.fail_json(msg="security group '%s' not found" % security_group_name)
        return sgs['securitygroup'][0]


    def add_rule(self):
        security_group = self.get_security_group()

        args = {}
        user_security_group_name = self.module.params.get('user_security_group')

        # the user_security_group and cidr are mutually_exclusive, but cidr is defaulted to 0.0.0.0/0.
        # that is why we ignore if we have a user_security_group.
        if user_security_group_name:
            args['usersecuritygrouplist'] = []
            user_security_group = self.get_security_group(user_security_group_name)
            args['usersecuritygrouplist'].append({
                'group': user_security_group['name'],
                'account': user_security_group['account'],
            })
        else:
            args['cidrlist'] = self.module.params.get('cidr')

        args['protocol']        = self.module.params.get('protocol')
        args['startport']       = self.module.params.get('start_port')
        args['endport']         = self.get_or_fallback('end_port', 'start_port')
        args['icmptype']        = self.module.params.get('icmp_type')
        args['icmpcode']        = self.module.params.get('icmp_code')
        args['projectid']       = self.get_project('id')
        args['securitygroupid'] = security_group['id']

        rule = None
        res  = None
        sg_type = self.module.params.get('type')
        if sg_type == 'ingress':
            rule = self._get_rule(security_group['ingressrule'])
            if not rule:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.authorizeSecurityGroupIngress(**args)

        elif sg_type == 'egress':
            rule = self._get_rule(security_group['egressrule'])
            if not rule:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.authorizeSecurityGroupEgress(**args)

        if res and 'errortext' in res:
            self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

        poll_async = self.module.params.get('poll_async')
        if res and poll_async:
            security_group = self._poll_job(res, 'securitygroup')
            key = sg_type + "rule" # ingressrule / egressrule
            if key in security_group:
                rule = security_group[key][0]
        return rule


    def remove_rule(self):
        security_group = self.get_security_group()
        rule = None
        res  = None
        sg_type = self.module.params.get('type')
        if sg_type == 'ingress':
            rule = self._get_rule(security_group['ingressrule'])
            if rule:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.revokeSecurityGroupIngress(id=rule['ruleid'])

        elif sg_type == 'egress':
            rule = self._get_rule(security_group['egressrule'])
            if rule:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.revokeSecurityGroupEgress(id=rule['ruleid'])

        if res and 'errortext' in res:
            self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

        poll_async = self.module.params.get('poll_async')
        if res and poll_async:
            res = self._poll_job(res, 'securitygroup')
        return rule


    def get_result(self, security_group_rule):
        super(AnsibleCloudStackSecurityGroupRule, self).get_result(security_group_rule)
        self.result['type'] = self.module.params.get('type')
        self.result['security_group'] = self.module.params.get('security_group')
        return self.result



def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        security_group = dict(required=True),
        type = dict(choices=['ingress', 'egress'], default='ingress'),
        cidr = dict(default='0.0.0.0/0'),
        user_security_group = dict(default=None),
        protocol = dict(choices=['tcp', 'udp', 'icmp', 'ah', 'esp', 'gre'], default='tcp'),
        icmp_type = dict(type='int', default=None),
        icmp_code = dict(type='int', default=None),
        start_port = dict(type='int', default=None, aliases=['port']),
        end_port = dict(type='int', default=None),
        state = dict(choices=['present', 'absent'], default='present'),
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
        mutually_exclusive = (
            ['icmp_type', 'start_port'],
            ['icmp_type', 'end_port'],
            ['icmp_code', 'start_port'],
            ['icmp_code', 'end_port'],
        ),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_sg_rule = AnsibleCloudStackSecurityGroupRule(module)

        state = module.params.get('state')
        if state in ['absent']:
            sg_rule = acs_sg_rule.remove_rule()
        else:
            sg_rule = acs_sg_rule.add_rule()

        result = acs_sg_rule.get_result(sg_rule)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
