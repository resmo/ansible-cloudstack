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
description: Add and remove security group rules.
version_added: '2.0'
author: René Moser
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
  user_security_group
    description:
      - Security group this rule is based of.
    required: false
    default: null
  start_port
    description:
      - Start port for this rule. Required if C(protocol=tcp) or C(protocol=udp).
    required: false
    default: null
    aliases: [ 'port' ]
  end_port
    description:
      - End port for this rule. Required if C(protocol=tcp) or C(protocol=udp), but C(start_port) will be used if not set.
    required: false
    default: null
  icmp_type
    description:
      - Type of the icmp message being sent. Required if C(protocol=icmp).
    required: false
    default: null
  icmp_code
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


class AnsibleCloudStackSecurityGroupRule(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)
        self.result = {
            'changed': False,
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
        end_port                 = self.module.params.get('end_port')
        icmp_code                = self.module.params.get('icmp_code')
        icmp_type                = self.module.params.get('icmp_type')

        if not end_port:
            end_port = start_port

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
        args['projectid'] = self.get_project_id()
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
        args['endport']         = self.module.params.get('end_port')
        args['icmptype']        = self.module.params.get('icmp_type')
        args['icmpcode']        = self.module.params.get('icmp_code')
        args['projectid']       = self.get_project_id()
        args['securitygroupid'] = security_group['id']

        if not args['endport']:
            args['endport'] = args['startport']

        rule = None
        res  = None
        type = self.module.params.get('type')
        if type == 'ingress':
            rule = self._get_rule(security_group['ingressrule'])
            if not rule:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.authorizeSecurityGroupIngress(**args)

        elif type == 'egress':
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
        return security_group


    def remove_rule(self):
        security_group = self.get_security_group()
        rule = None
        res  = None
        type = self.module.params.get('type')
        if type == 'ingress':
            rule = self._get_rule(security_group['ingressrule'])
            if rule:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.revokeSecurityGroupIngress(id=rule['ruleid'])

        elif type == 'egress':
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
        return security_group


    def get_result(self, security_group_rule):
        type = self.module.params.get('type')
        
        key = 'ingressrule'
        if type == 'egress':
            key = 'egressrule'

        self.result['type'] = type
        self.result['security_group'] = self.module.params.get('security_group')

        if key in security_group_rule and security_group_rule[key]:
            if 'securitygroupname' in security_group_rule[key][0]:
                self.result['user_security_group'] = security_group_rule[key][0]['securitygroupname']
            if 'cidr' in security_group_rule[key][0]:
                self.result['cidr'] = security_group_rule[key][0]['cidr']
            if 'protocol' in security_group_rule[key][0]:
                self.result['protocol'] = security_group_rule[key][0]['protocol']
            if 'startport' in security_group_rule[key][0]:
                self.result['start_port'] = security_group_rule[key][0]['startport']
            if 'endport' in security_group_rule[key][0]:
                self.result['end_port'] = security_group_rule[key][0]['endport']
            if 'icmpcode' in security_group_rule[key][0]:
                self.result['icmp_code'] = security_group_rule[key][0]['icmpcode']
            if 'icmptype' in security_group_rule[key][0]:
                self.result['icmp_type'] = security_group_rule[key][0]['icmptype']
        return self.result


def main():
    module = AnsibleModule(
        argument_spec = dict(
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
            poll_async = dict(choices=BOOLEANS, default=True),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
        ),
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

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
