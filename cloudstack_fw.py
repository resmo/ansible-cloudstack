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
module: cloudstack_fw
short_description: Create and remove firewall rules on Apache CloudStack based clouds.
description:
    - Manage firewall rules on Apache CloudStack, Citrix CloudPlatform
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), C(api_http_method), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  ip_address:
    description:
      - Public IP address the rule is assigned to.
    required: true
    default: null
    aliases: []
  state:
    description:
      - State of the firewall rule.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
    aliases: []
  protocol:
    description:
      - Protocol of the firewall rule.
    required: false
    default: 'tcp'
    choices: [ 'tcp', 'udp', 'icmp' ]
    aliases: []
  cidr:
    description:
      - CIDR (full notation) to be used for firewall rule.
    required: false
    default: '0.0.0.0\0'
    aliases: []
  start_port
    description:
      - Start port for this rule. Considered if C(protocol=tcp) or C(protocol=udp).
    required: false
    default: null
    aliases: []
  end_port
    description:
      - End port for this rule. Considered if C(protocol=tcp) or C(protocol=udp).
    required: false
    default: null
    aliases: []
  icmp_type
    description:
      - Type of the icmp message being sent. Considered if C(protocol=icmp).
    required: false
    default: null
    aliases: []
  icmp_code
    description:
      - Error code for this icmp message. Considered if C(protocol=icmp).
    required: false
    default: null
    aliases: []
  project:
    description:
      - Name of the project.
    required: false
    default: null
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
# Allow inbound port 80/tcp from 1.2.3.4 to 4.3.2.1
- local_action:
    module: cloudstack_fw
    ip_address: 4.3.2.1
    start_port: 80
    end_port: 80
    cidr: 1.2.3.4/32


# Allow inbound tcp/udp port 53 to 4.3.2.1
- local_action:
    module: cloudstack_fw
    ip_address: 4.3.2.1
    start_port: 53
    end_port: 53
    protocol: '{{ item }}'
  with_items:
  - tcp
  - udp

'''

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required: pip install cs'")
    sys.exit(1)


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


def get_ip_address_id(module, cs, project_id):
    args = {}
    args['ipaddress'] = module.params.get('ip_address')
    args['projectid'] = project_id
    ip_addresses = cs.listPublicIpAddresses(**args)

    if not ip_addresses:
        module.fail_json(msg="ip address '%s' not found" % args['ipaddress'])

    return ip_addresses['publicipaddress'][0]['id']


def get_firewall_rules(module, cs, ip_address_id, project_id):
    args = {}
    args['ipaddressid'] = ip_address_id

    if project_id:
        args['projectid'] = project_id

    firewall_rules = cs.listFirewallRules(**args)
    if firewall_rules and 'firewallrule' in firewall_rules:
        return firewall_rules['firewallrule']
    else:
        return {}


def get_firewall_rule(module, cs, ip_address_id, project_id):
    cidr = module.params.get('cidr')
    protocol = module.params.get('protocol')

    start_port = module.params.get('start_port')
    end_port = module.params.get('end_port')

    icmp_code = module.params.get('icmp_code')
    icmp_type = module.params.get('icmp_type')

    if protocol in ['tcp', 'udp'] and not (start_port and end_port):
        module.fail_json(msg="no start_port or end_port set for protocol '%s'" % protocol)

    if protocol == 'icmp' and not icmp_type:
        module.fail_json(msg="no icmp_type set")

    firewall_rules = get_firewall_rules(module, cs, ip_address_id, project_id)
    for rule in firewall_rules:
        type_match = type_cidr_match(rule, cidr)

        protocol_match = tcp_udp_match(rule, protocol, start_port, end_port) \
            or icmp_match(rule, protocol, icmp_code, icmp_type)

        if type_match and protocol_match:
            return rule
    return None


def tcp_udp_match(rule, protocol, start_port, end_port):
    return protocol in ['tcp', 'udp'] \
        and protocol == rule['protocol'] \
        and start_port == int(rule['startport']) \
        and end_port == int(rule['endport'])


def icmp_match(rule, protocol, icmp_code, icmp_type):
    return protocol == 'icmp' \
       and protocol == rule['protocol'] \
       and icmp_code == rule['icmpcode'] \
       and icmp_type == rule['icmptype']


def type_cidr_match(rule, cidr):
    return cidr == rule['cidrlist']


def create_firewall_rule(module, cs, result, project_id):
    ip_address_id = get_ip_address_id(module, cs, project_id)
    firewall_rule = get_firewall_rule(module, cs, ip_address_id, project_id)

    if not firewall_rule:
        result['changed'] = True
        args = {}
        args['cidrlist'] = module.params.get('cidr')
        args['protocol'] = module.params.get('protocol')
        args['startport'] = module.params.get('start_port')
        args['endport'] = module.params.get('end_port')
        args['icmptype'] = module.params.get('icmp_type')
        args['icmpcode'] = module.params.get('icmp_code')
        args['ipaddressid'] = ip_address_id

        if not module.check_mode:
            firewall_rule = cs.createFirewallRule(**args)

    return (result, firewall_rule)


def remove_firewall_rule(module, cs, result, project_id):
    ip_address_id = get_ip_address_id(module, cs, project_id)
    firewall_rule = get_firewall_rule(module, cs, ip_address_id, project_id)

    if firewall_rule:
        result['changed'] = True
        args = {}
        args['id'] = firewall_rule['id']

        if not module.check_mode:
            res = cs.deleteFirewallRule(**args)

    return (result, firewall_rule)


def main():
    module = AnsibleModule(
        argument_spec = dict(
            ip_address = dict(required=True, default=None),
            cidr = dict(default='0.0.0.0/0'),
            protocol = dict(choices=['tcp', 'udp', 'icmp'], default='tcp'),
            icmp_type = dict(type='int', default=None),
            icmp_code = dict(type='int', default=None),
            start_port = dict(type='int', default=None),
            end_port = dict(type='int', default=None),
            state = dict(choices=['present', 'absent'], default='present'),
            project = dict(default=None),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
        ),
        required_together = (
            ['start_port', 'end_port'],
        ),
        mutually_exclusive = (
            ['icmp_type', 'start_port'],
            ['icmp_type', 'end_port'],
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

        if state in ['absent']:
            (result, firewall_rule) = remove_firewall_rule(module, cs, result, project_id)

        elif state in ['present']:
            (result, firewall_rule) = create_firewall_rule(module, cs, result, project_id)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
