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

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required. pip install cs'")
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


def register_ssh_key(module, cs, result, ssh_key, project_id):
    if not ssh_key:
        args = {}
        if project_id:
            args['projectid'] = project_id

        result['changed'] = True
        if not module.check_mode:
            args['name'] = module.params.get('name')
            args['publickey'] = module.params.get('public_key')
            ssh_key = cs.registerSSHKeyPair(**args)
    return (result, ssh_key)


def create_ssh_key(module, cs, result, ssh_key, project_id):
    if not ssh_key:
        args = {}
        if project_id:
            args['projectid'] = project_id

        result['changed'] = True
        if not module.check_mode:
            args['name'] = module.params.get('name')
            res = cs.createSSHKeyPair(**args)
            ssh_key = res['keypair']
    return (result, ssh_key)


def remove_ssh_key(module, cs, result, ssh_key):
    if ssh_key:
        result['changed'] = True
        if not module.check_mode:
            args = {}
            args['name'] = module.params.get('name')
            res = cs.deleteSSHKeyPair(**args)
    return (result, ssh_key)


def get_ssh_key(module, cs, project_id):

    args = {}

    if project_id:
        args['projectid'] = project_id

    args['name'] = module.params.get('name')

    ssh_keys = cs.listSSHKeyPairs(**args)

    if ssh_keys:
        return ssh_keys['sshkeypair'][0]

    return None

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

    result = {}
    result['changed'] = False
    state = module.params.get('state')

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
        ssh_key = get_ssh_key(module, cs, project_id)

        if state in ['absent']:
            (result, ssh_key) = remove_ssh_key(module, cs, result, ssh_key)
        else:
            if module.params.get('public_key'):
                (result, ssh_key) = register_ssh_key(module, cs, result, ssh_key, project_id)
            else:
                (result, ssh_key) = create_ssh_key(module, cs, result, ssh_key, project_id)
    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    if ssh_key:
        if 'fingerprint' in ssh_key:
            result['fingerprint'] = ssh_key['fingerprint']

        if 'name' in ssh_key:
            result['name'] = ssh_key['name']

        if 'privatekey' in ssh_key:
            result['private_key'] = ssh_key['privatekey']

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
