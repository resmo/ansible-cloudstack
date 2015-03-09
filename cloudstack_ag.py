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
module: cloudstack_ag
short_description: Create and remove affinity groups on Apache CloudStack based clouds.
description:
    - Manage affinity groups on Apache CloudStack, Citrix CloudPlatform and Exoscale
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), C(api_http_method), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  name:
    description:
      - Name of the affinity group.
    required: true
    default: null
    aliases: []
  affinty_type:
    description:
      - Type of the affinity group.
    required: false
    default: null
    aliases: []
  description:
    description:
      - Description of the affinity group.
    required: false
    default: null
    aliases: []
  state:
    description:
      - State of the affinity group.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
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
# Create a affinity group
- local_action:
    module: cloudstack_ag
    name: haproxy
    affinty_type: host anti-affinity


# Remove a affinity group
- local_action:
    module: cloudstack_ag
    name: haproxy
    state: absent
'''

import sys

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required: pip install cs'")
    sys.exit(1)


def get_affinity_group(module, cs):
    ag_name = module.params.get('name')

    ags = cs.listAffinityGroups()
    if ags:
        for a in ags['affinitygroup']:
            if a['name'] == ag_name:
                return a
    return None


def create_affinity_group(module, cs, result, affinity_group, affinity_type):
    if not affinity_group:
        args = {}
        args['name'] = module.params.get('name')
        args['type'] = affinity_type
        args['description'] = module.params.get('description')

        if not module.check_mode:
            affinity_group = cs.createAffinityGroup(**args)

            if 'errortext' in affinity_group:
                module.fail_json(msg="Failed: '%s'" % affinity_group['errortext'])

        result['changed'] = True
    return (result, affinity_group)


def remove_affinity_group(module, cs, result, affinity_group):
    if affinity_group:
        args = {}
        args['name'] = module.params.get('name')

        if not module.check_mode:
            affinity_group = cs.deleteAffinityGroup(**args)

            if 'errortext' in affinity_group:
                module.fail_json(msg="Failed: '%s'" % affinity_group['errortext'])

        result['changed'] = True
    return (result, affinity_group)


def get_affinity_type(module, cs):
    affinity_type = module.params.get('affinty_type')

    affinity_types = cs.listAffinityGroupTypes()

    if affinity_types:
        if not affinity_type:
            return affinity_types['affinityGroupType'][0]

        for a in affinity_types['affinityGroupType']:
            if a['type'] == affinity_type:
                return a['type']
    module.fail_json(msg="affinity group type '%s' not found" % affinity_type)


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True, default=None),
            affinty_type = dict(default=None),
            description = dict(default=None),
            state = dict(choices=['present', 'absent'], default='present'),
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

        affinity_group = get_affinity_group(module, cs)
        affinty_type = get_affinity_type(module, cs)

        if state in ['absent']:
            (result, affinity_group) = remove_affinity_group(module, cs, result, affinity_group)

        elif state in ['present']:
            (result, affinity_group) = create_affinity_group(module, cs, result, affinity_group, affinty_type)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
