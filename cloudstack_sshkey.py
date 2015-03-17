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
---
module: cloudstack_sshkey
short_description: Create, register and remove ssh keys on Apache CloudStack based clouds.
description:
    - If no public key is provided, a new ssh private/public key will be created, the private key will be returned.
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), C(api_http_method), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  name:
    description:
      - Name of public key.
    required: true
    default: null
    aliases: []
  project:
    description:
      - Name of the project the public key to be registered in.
    required: false
    default: null
    aliases: []
  state:
    description:
      - State of the public key.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
    aliases: []
  public_key:
    description:
      - String of the public key.
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
requirements: [ 'cs' ]
'''

EXAMPLES = '''
---
# create a new private / public key:
- cloudstack_sshkey: name=linus@example.com
  register: key

- debug: msg='private key is {{ key.private_key }}'


# remove a public key:
- cloudstack_sshkey: name=linus@example.com state=absent


# register a your local public key:
- cloudstack_sshkey: name=linus@example.com public_key='{{ lookup('file', '~/.ssh/id_rsa.pub') }}'
'''

import sys

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required: pip install cs'")
    sys.exit(1)


class AnsibleCloudStack:

    def __init__(self, module):
        self.module = module
        self._connect()

        self.project_id = None
        self.ip_address_id = None
        self.zone_id = None
        self.vm_id = None
        self.os_type_id = None


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


    def get_project_id(self):
        if self.project_id:
            return self.project_id

        project = self.module.params.get('project')
        if not project:
            return None

        projects = self.cs.listProjects()
        if projects:
            for p in projects['project']:
                if project in [ p['name'], p['displaytext'], p['id'] ]:
                    self.project_id = p[id]
                    return self.project_id
        self.module.fail_json(msg="project '%s' not found" % project)


    def get_ip_address_id(self):
        if self.ip_address_id:
            return self.ip_address_id

        args = {}
        args['ipaddress'] = self.module.params.get('ip_address')
        args['projectid'] = self.get_project_id()
        ip_addresses = self.cs.listPublicIpAddresses(**args)

        if not ip_addresses:
            self.module.fail_json(msg="ip address '%s' not found" % args['ipaddress'])

        self.ip_address_id = ip_addresses['publicipaddress'][0]['id']
        return self.ip_address_id


    def get_vm_id(self):
        if self.vm_id:
            return self.vm_id

        vm = self.module.params.get('vm')
        args['projectid'] = self.get_project_id()
        vms = self.cs.listVirtualMachines(**args)
        if vms:
            for v in vms['virtualmachine']:
                if vm in [ v['name'], v['id'] ]:
                    self.vm_id = v['id']
                    return self.vm_id
        self.module.fail_json(msg="Virtual machine '%s' not found" % vm)


    def get_zone_id(self):
        if self.zone_id:
            return self.zone_id

        zone = self.module.params.get('zone')
        zones = self.cs.listZones()

        # use the first zone if no zone param
        if not zone:
            self.zone_id = zones['zone'][0]['id']
            return self.zone_id

        if zones:
            for z in zones['zone']:
                if zone in [ z['name'], z['id'] ]:
                    self.zone_id = z['id']
                    return self.zone_id
        self.module.fail_json(msg="zone '%s' not found" % zone)


    def get_os_type_id(self):
        if self.os_type_id:
            return self.os_type_id

        os_type = self.module.params.get('os_type')
        if not os_type:
            return None

        os_types = self.cs.listOsTypes()
        if os_types:
            for o in os_types['ostype']:
                if os_type in [ o['description'], o['id'] ]:
                    self.os_type_id = o['id']
                    return self.os_type_id
        self.module.fail_json(msg="OS type '%s' not found" % os_type)


    def _poll_job(self, job, key):
        if 'jobid' in job:
            while True:
                res = self.cs.queryAsyncJobResult(jobid=job['jobid'])
                if res['jobstatus'] != 0:
                    if 'jobresult' in res and key in res['jobresult']:
                        job = res['jobresult'][key]
                    break
                time.sleep(2)
        return job


class AnsibleCloudStackSshKey(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)
        self.result = {
            'changed': False,
        }


    def register_ssh_key(self, ssh_key):
        if not ssh_key:
            args = {}
            args['projectid'] = self.get_project_id()

            self.result['changed'] = True
            if not self.module.check_mode:
                args['name'] = self.module.params.get('name')
                args['publickey'] = self.module.params.get('public_key')
                ssh_key = self.cs.registerSSHKeyPair(**args)
        return ssh_key


    def create_ssh_key(self, ssh_key):
        if not ssh_key:
            args = {}
            args['projectid'] = self.get_project_id()
            
            self.result['changed'] = True
            if not self.module.check_mode:
                args['name'] = self.module.params.get('name')
                res = self.cs.createSSHKeyPair(**args)
                ssh_key = res['keypair']
            return ssh_key


    def remove_ssh_key(self, ssh_key):
        if ssh_key:
            self.result['changed'] = True
            if not self.module.check_mode:
                args = {}
                args['name'] = self.module.params.get('name')
                res = self.cs.deleteSSHKeyPair(**args)
        return ssh_key


    def get_ssh_key(self):
        args = {}
        args['projectid'] = self.get_project_id()
        args['name'] = self.module.params.get('name')

        ssh_keys = self.cs.listSSHKeyPairs(**args)
        if ssh_keys and 'sshkeypair' in ssh_keys:
            return ssh_keys['sshkeypair'][0]
        return None


    def get_result(self, ssh_key):
        if ssh_key:
            if 'fingerprint' in ssh_key:
                self.result['fingerprint'] = ssh_key['fingerprint']

            if 'name' in ssh_key:
                self.result['name'] = ssh_key['name']

            if 'privatekey' in ssh_key:
                self.result['private_key'] = ssh_key['privatekey']
        return self.result


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True, default=None),
            public_key = dict(default=None),
            project = dict(default=None),
            state = dict(choices=['present', 'absent'], default='present'),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
        ),
        supports_check_mode=True
    )

    try:
        ansible_cloudstack_sshkey = AnsibleCloudStackSshKey(module)
        ssh_key = ansible_cloudstack_sshkey.get_ssh_key()

        state = module.params.get('state')
        if state in ['absent']:
            ssh_key = ansible_cloudstack_sshkey.remove_ssh_key(ssh_key)
        else:
            if module.params.get('public_key'):
                ssh_key = ansible_cloudstack_sshkey.register_ssh_key(ssh_key)
            else:
                ssh_key = ansible_cloudstack_sshkey.create_ssh_key(ssh_key)

        result = ansible_cloudstack_sshkey.get_result(ssh_key)
    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
