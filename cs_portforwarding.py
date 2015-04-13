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
module: cloudstack_pf
short_description: Create and remove port forwarding rules on Apache CloudStack based clouds.
description:
    - Manage port forwarding rules on Apache CloudStack, Citrix CloudPlatform
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
  vm:
    description:
      - Name of virtual machine which we make the port forwardingrule for. Required if C(state=present).
    required: false
    default: null
    aliases: []
  state:
    description:
      - State of the port forwarding rule.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
    aliases: []
  protocol:
    description:
      - Protocol of the port forwarding rule.
    required: false
    default: 'tcp'
    choices: [ 'tcp', 'udp' ]
    aliases: []
  public_port
    description:
      - Start public port for this rule.
    required: true
    default: null
    aliases: []
  public_end_port
    description:
      - End public port for this rule.
    required: false
    default: null
    aliases: []
  private_port
    description:
      - Start private port for this rule.
    required: true
    default: null
    aliases: []
  private_end_port
    description:
      - End private port for this rule.
    required: false
    default: null
    aliases: []
  open_firewall:
    description:
      - Whether the firewall rule for public port should be created.
    required: false
    default: false
    aliases: []
  vm_guest_ip:
    description:
      - VM guest NIC secondary IP address for the port forwarding rule.
    required: false
    default: false
    aliases: []
  project:
    description:
      - Name of the project the VM is located in.
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
- name: 1.2.3.4:80 -> web01:8080
  local_action:
    module: cloudstack_pf
    ip_address: 1.2.3.4
    vm: web01
    public_port: 80
    private_port: 8080


- name: open ssh port and firewall
  local_action:
    module: cloudstack_pf
    ip_address: '{{ public_ip }}'
    vm: '{{ inventory_hostname }}'
    public_port: '{{ ansible_ssh_port }}'
    private_port: 22
    open_firewall: true

- name: remove ssh portforwarding
  local_action:
    module: cloudstack_pf
    ip_address: 1.2.3.4
    public_port: 22
    private_port: 22
    state: absent

'''

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

# import cloudstack common
#from ansible.module_utils.cloudstack import *


class AnsibleCloudStackPortforwarding(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)
        self.result = {
            'changed': False,
        }
        self.portforwarding_rule = None


    def get_portforwarding_rule(self):
        if not self.portforwarding_rule:
            protocol = self.module.params.get('protocol')
            public_port = self.module.params.get('public_port')
            public_end_port = self.module.params.get('public_end_port')
            if not public_end_port:
                public_end_port = public_port
            
            private_port = self.module.params.get('private_port')
            private_end_port = self.module.params.get('private_end_port')
            if not private_end_port:
                private_end_port = private_port

            args = {}
            args['ipaddressid'] = self.get_ip_address_id()
            args['projectid'] = self.get_project_id()
            portforwarding_rules = self.cs.listPortForwardingRules(**args)

            if portforwarding_rules and 'portforwardingrule' in portforwarding_rules:
                for rule in portforwarding_rules['portforwardingrule']:
                    if protocol == rule['protocol'] \
                        and public_port == int(rule['publicport']) \
                        and public_end_port == int(rule['publicendport']) \
                        and private_port == int(rule['privateport']) \
                        and private_end_port == int(rule['privateendport']):
                        self.portforwarding_rule = rule
                        break
        return self.portforwarding_rule


    def create_portforwarding_rule(self):
        portforwarding_rule = self.get_portforwarding_rule()

        args = {}
        args['protocol'] = self.module.params.get('protocol')
        args['publicport'] = self.module.params.get('public_port')
        args['publicendport'] = self.module.params.get('public_end_port')
        args['privateport'] = self.module.params.get('private_port')
        args['privateendport'] = self.module.params.get('private_end_port')

        args['ipaddressid'] = self.get_ip_address_id()
        args['openfirewall'] = self.module.params.get('open_firewall')
        args['vmguestip'] = self.module.params.get('vm_guest_ip')
        args['virtualmachineid'] = self.get_vm_id()
        poll_async = self.module.params.get('poll_async')

        if not portforwarding_rule:
            self.result['changed'] = True
            if not self.module.check_mode:
                portforwarding_rule = self.cs.createPortForwardingRule(**args)
                if poll_async:
                    portforwarding_rule = self._poll_job(portforwarding_rule, 'portforwardingrule')
        else:
            vm_id = self.get_vm_id()
            if vm_id != portforwarding_rule['virtualmachineid']:
                self.result['changed'] = True
                if not self.module.check_mode:
                    # Seems broken in 4.2.1?, implementing workaround
                    # portforwarding_rule = self.cs.updatePortForwardingRule(**args)
                    self.remove_portforwarding_rule()
                    portforwarding_rule = self.cs.createPortForwardingRule(**args)
                    if poll_async:
                        portforwarding_rule = self._poll_job(portforwarding_rule, 'portforwardingrule')
        return portforwarding_rule


    def remove_portforwarding_rule(self):
        portforwarding_rule = self.get_portforwarding_rule()

        if portforwarding_rule:
            self.result['changed'] = True
            args = {}
            args['id'] = portforwarding_rule['id']

            if not self.module.check_mode:
                res = self.cs.deletePortForwardingRule(**args)
                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    self._poll_job(res, 'portforwardingrule')

        return portforwarding_rule


    def get_result(self, portforwarding_rule):
        return self.result


def main():
    module = AnsibleModule(
        argument_spec = dict(
            ip_address = dict(required=True),
            protocol = dict(choices=['tcp', 'udp'], default='tcp'),
            public_port = dict(type='int', required=True, default=None),
            public_end_port = dict(type='int', default=None),
            private_port = dict(type='int', required=True, default=None),
            private_end_port = dict(type='int', default=None),
            state = dict(choices=['present', 'absent'], default='present'),
            open_firewall = dict(choices=BOOLEANS, default=False),
            vm_guest_ip = dict(default=None),
            vm = dict(default=None),
            project = dict(default=None),
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
        acs_pf = AnsibleCloudStackPortforwarding(module)
        state = module.params.get('state')
        if state in ['absent']:
            pf_rule = acs_pf.remove_portforwarding_rule()
        else:
            pf_rule = acs_pf.create_portforwarding_rule()

        result = acs_pf.get_result(pf_rule)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
