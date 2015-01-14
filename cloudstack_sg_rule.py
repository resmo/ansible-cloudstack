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
module: cloudstack_sg_rules
short_description: Create and remove security group rules on Apache CloudStack based clouds.
description:
    - Manage security group rules on Apache CloudStack, Citrix CloudPlatform and Exoscale
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  name:
    description:
      - Name of the security group.
    required: true
    default: null
    aliases: []
  state:
    description:
      - State of the security group rule.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
    aliases: []
  protocol:
    description:
      - Protocol of the security group rule.
    required: false
    default: 'tcp'
    choices: [ 'tcp', 'udp', 'icmp', 'ah', 'esp', 'gre' ]
    aliases: []
  flow:
    description:
      - Inbound or outbound security group rule.
    required: false
    default: 'inbound'
    choices: [ 'inbound', 'outbound' ]
    aliases: []
  cidr:
    description:
      - CIDR (full notation) to be used for security group rule.
    required: false
    default: '0.0.0.0\0'
    aliases: []
  user_security_group
    description:
      - Security group this rule is based of.
    required: false
    default: null
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
      - Name of the project the security group to be created in.
    required: false
    default: null
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
author: René Moser
requirements: [ 'python library C(cs)' ]
'''

EXAMPLES = '''
---
# Allow inbound port 80/tcp from 1.2.3.4 added to security group 'default'
- local_action:
    module: cloudstack_sg_rule
    name: default
    start_port: 80
    end_port: 80
    cidr: 1.2.3.4/32


# Allow tcp/udp outbound added to security group 'default'
- local_action:
    module: cloudstack_sg_rule
    name: default
    flow: outbound
    start_port: 1
    end_port: 65535
    protocol: '{{ item }}'
  with_items:
  - tcp
  - udp


# Allow inbound icmp from 0.0.0.0/0 added to security group 'default'
- local_action:
    module: cloudstack_sg_rule
    name: default
    protocol: icmp
    icmp_code: -1
    icmp_type: -1


# Remove rule inbound port 80/tcp from 0.0.0.0/0 from security group 'default'
- local_action:
    module: cloudstack_sg_rule
    name: default
    start_port=80
    end_port=80
    state: absent


# Allow inbound port 80/tcp from security group web added to security group 'default'
- local_action:
    module: cloudstack_sg_rule
    name: default
    start_port: 80
    end_port: 80
    user_security_group=web
'''

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required: pip install cs'")
    sys.exit(1)


def get_security_group(module, cs, security_group_name, project_id):
    sg = cs.listSecurityGroups(projectid=project_id, securitygroupname=security_group_name)
    if not sg:
        module.fail_json(msg="security group '%s' not found" % security_group_name)
    return sg['securitygroup'][0]


def add_rule(module, cs, result, security_group, project_id):
    args = {}
    args['protocol'] = module.params.get('protocol')
    user_security_group_name = module.params.get('user_security_group')
    if user_security_group_name:
        args['usersecuritygrouplist'] = []
        user_security_group = get_security_group(module, cs, user_security_group_name, project_id)
        args['usersecuritygrouplist'].append({
            'group': user_security_group['name'],
            'account': user_security_group['account'],
        })
    else:
        args['cidrlist'] = module.params.get('cidr')
    args['startport'] = module.params.get('start_port')
    args['endport'] = module.params.get('end_port')
    args['icmptype'] = module.params.get('icmp_type')
    args['icmpcode'] = module.params.get('icmp_code')
    args['securitygroupid'] = security_group['id']

    if args['protocol'] in ['tcp', 'udp'] and not (args['startport'] or args['endport']):
        module.fail_json(msg="no start_port or end_port set for protocol '%s'" % args['protocol'])

    if args['protocol'] == 'icmp' and not args['icmptype']:
        module.fail_json(msg="no icmp_type set")

    rule = None
    job = None
    flow = module.params.get('flow')
    if flow == 'inbound':
        rule = get_rule(security_group['ingressrule'], module)
        if not rule:
            result['changed'] = True
            if not module.check_mode:
                job = cs.authorizeSecurityGroupIngress(**args)

    elif flow == 'outbound':
        rule = get_rule(security_group['egressrule'], module)
        if not rule:
            result['changed'] = True
            if not module.check_mode:
                job = cs.authorizeSecurityGroupEgress(**args)

    if job and 'errortext' in job:
        module.fail_json(msg="Failed: '%s'" % job['errortext'])

    poll_async = module.params.get('poll_async')
    if job and poll_async:
        security_group = poll_job(cs, job, 'securitygroup')

    return (result, security_group)


def tcp_udp_match(rule, protocol, start_port, end_port):
    return protocol in ['tcp', 'udp'] \
           and start_port == rule['startport'] \
           and end_port == rule['endport']


def icmp_match(rule, protocol, icmp_code, icmp_type):
    return protocol == 'icmp' \
           and icmp_code == rule['icmpcode'] \
           and icmp_type == rule['icmptype']

def ah_esp_gre_match(protocol):
    return protocol in ['ah', 'esp', 'gre']

def type_security_group_match(rule, security_group_name, protocol):
    return 'securitygroupname' in rule \
           and security_group_name == rule['securitygroupname'] \
           and protocol == rule['protocol']

def type_cidr_match(rule, cidr, protocol):
    return 'cidr' in rule \
           and cidr == rule['cidr'] \
           and protocol == rule['protocol']


def get_rule(rules, module):
    user_security_group_name = module.params.get('user_security_group')
    cidr = module.params.get('cidr')
    protocol = module.params.get('protocol')
    start_port = module.params.get('start_port')
    end_port = module.params.get('end_port')
    icmp_code = module.params.get('icmp_code')
    icmp_type = module.params.get('icmp_type')

    for rule in rules:
        type_match = (user_security_group_name and type_security_group_match(rule, user_security_group_name, protocol)) \
            or (not user_security_group_name and type_cidr_match(rule, cidr, protocol))

        protocol_match = tcp_udp_match(rule, protocol, start_port, end_port) \
            or icmp_match(rule, protocol, icmp_code, icmp_type) \
            or ah_esp_gre_match(protocol)

        if type_match and protocol_match:
            return rule

    return None


def remove_rule(module, cs, result, security_group):
    flow = module.params.get('flow')

    rule = None
    job = None
    if flow == 'inbound':
        rule = get_rule(security_group['ingressrule'], module)
        if rule:
            result['changed'] = True
            if not module.check_mode:
                job = cs.revokeSecurityGroupIngress(id=rule['ruleid'])

    elif flow == 'outbound':
        rule = get_rule(security_group['egressrule'], module)
        if rule:
            result['changed'] = True
            if not module.check_mode:
                job = cs.revokeSecurityGroupEgress(id=rule['ruleid'])

    if job and 'errortext' in job:
        module.fail_json(msg="Failed: '%s'" % job['errortext'])

    poll_async = module.params.get('poll_async')
    if job and poll_async:
        security_group = poll_job(cs, job, 'securitygroup')

    return (result, security_group)


def get_project_id(module, cs):
    project = module.params.get('project')
    if not project:
        return ''

    projects = cs.listProjects()
    if projects:
        for p in projects['project']:
            if p['name'] == project or p['id'] == project:
                return p['id']
    module.fail_json(msg="project '%s' not found" % project)


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
            flow = dict(choices=['inbound', 'outbound'], default='inbound'),
            cidr = dict(default='0.0.0.0/0'),
            user_security_group = dict(default=None),
            protocol = dict(choices=['tcp', 'udp', 'icmp', 'ah', 'esp', 'gre'], default='tcp'),
            icmp_type = dict(type='int', default=None),
            icmp_code = dict(type='int', default=None),
            start_port = dict(type='int', default=None),
            end_port = dict(type='int', default=None),
            state = dict(choices=['present', 'absent'], default='present'),
            project = dict(default=None),
            poll_async = dict(choices=BOOLEANS, default=True),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
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

        if api_key and api_secret and api_url:
            cs = CloudStack(
                endpoint=api_url,
                key=api_key,
                secret=api_secret
                )
        else:
            cs = CloudStack(**read_config())

        project_id = get_project_id(module, cs)
        security_group_name = module.params.get('name')
        security_group = get_security_group(module, cs, security_group_name, project_id)

        if state in ['absent']:
            (result, security_group) = remove_rule(module, cs, result, security_group)

        elif state in ['present']:
            (result, security_group) = add_rule(module, cs, result, security_group, project_id)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
