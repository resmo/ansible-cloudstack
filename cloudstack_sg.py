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
module: cloudstack_sg
short_description: Create and remove security groups on Apache CloudStack based clouds.
description:
    - Manage security groups on Apache CloudStack, Citrix CloudPlatform and Exoscale
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), C(api_http_method), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  name:
    description:
      - Name of the security group.
    required: true
    default: null
    aliases: []
  description:
    description:
      - Description of the security group.
    required: false
    default: null
    aliases: []
  state:
    description:
      - State of the security group.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
    aliases: []
  project:
    description:
      - Name of the project the security group to be created in.
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
# Create a security group
- local_action:
    module: cloudstack_sg
    name: default
    description: default security group


# Remove a security group
- local_action:
    module: cloudstack_sg
    name: default
    state: absent
'''

import sys

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required: pip install cs'")
    sys.exit(1)


def get_security_group(module, cs, project_id):
    sg_name = module.params.get('name')

    sgs = cs.listSecurityGroups(projectid=project_id)
    if sgs:
        for s in sgs['securitygroup']:
            if s['name'] == sg_name:
                return s
    return None


def create_security_group(module, cs, result, security_group, project_id):
    if not security_group:
        args = {}
        args['projectid'] = project_id
        args['name'] = module.params.get('name')
        args['description'] = module.params.get('description')

        if not module.check_mode:
            security_group = cs.createSecurityGroup(**args)

            if 'errortext' in security_group:
                module.fail_json(msg="Failed: '%s'" % security_group['errortext'])

        result['changed'] = True
    return (result, security_group)


def remove_security_group(module, cs, result, security_group,project_id):
    if security_group:
        args = {}
        args['projectid'] = project_id
        args['name'] = module.params.get('name')

        if not module.check_mode:
            security_group = cs.deleteSecurityGroup(**args)

            if 'errortext' in security_group:
                module.fail_json(msg="Failed: '%s'" % security_group['errortext'])

        result['changed'] = True
    return (result, security_group)


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


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True, default=None),
            description = dict(default=None),
            state = dict(choices=['present', 'absent'], default='present'),
            project = dict(default=None),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
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
        security_group = get_security_group(module, cs, project_id)

        if state in ['absent']:
            (result, security_group) = remove_security_group(module, cs, result, security_group, project_id)

        elif state in ['present']:
            (result, security_group) = create_security_group(module, cs, result, security_group, project_id)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
