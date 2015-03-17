#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015, Dong Xie <dong.xie@interoute.com>
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
module: cloudstack_template
short_description: Register and delete Templates on Apache CloudStack based clouds.
description:
    - Manage Templates on Apache CloudStack, Citrix CloudPlatform and Exoscale.
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), C(api_http_method), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  name:
    description:
      - Name of the Template.
    required: true
    default: null
    aliases: []
  url:
    description:
      - URL of where the template is hosted. Required if C(state) is present.
    required: false
    default: null
    aliases: []
  os_type:
    description:
      - the ID of the OS Type that best represents the OS of this template.
    required: false
    default: null
    aliases: []
  is_ready:
    description:
      - This flag is used for searching existing templates. If set to C(true), it will only list template ready for deployment e.g. successfully downloaded and installed. Recommended to set it to C(false).
    required: false
    default: false
    aliases: []
  is_public:
    description:
      - Register the template to be publicly available to all users. Only used if C(state) is present.
    required: false
    default: false
    aliases: []
  is_featured:
    description:
      - Register the template to be featured. Only used if C(state) is present.
    required: false
    default: false
    aliases: []
  is_dynamically_scalable:
    description:
      - Register the template having XS/VMWare tools installed in order to support 
        dynamic scaling of VM cpu/memory. Only used if C(state) is present.
    required: false
    default: false
    aliases: []
  checksum:
    description:
      - The MD5 checksum value of this template. If set, we search by checksum instead of name.
    required: false
    default: false
    aliases: []
  project:
    description:
      - Name of the project the template to be registered in.
    required: false
    default: null
    aliases: []
  zone:
    description:
      - Name of the zone you wish the template to be registered or deleted from. If
        not specified, all zones will be used.
    required: false
    default: null
    aliases: []
  templatefilter:
    description:
      - Name of the filter used to search for the template.
    required: false
    default: 'self'
    choices: [ 'featured', 'self', 'selfexecutable','sharedexecutable','executable', 'community' ]
    aliases: []
  hypervisor:
    description:
      - the target hypervisor for the template.
    required: true
    default: null
    aliases: []
  requireshvm:
    description:
      - true if this template requires HVM.
    required: false
    default: false
    aliases: []
  passwordenabled:
    description:
      - true if the template supports the password reset feature.
    required: false
    default: false
    aliases: []
  templatetag:
    description:
      - the tag for this template.
    required: false
    default: null
    aliases: []
  sshkeyenabled:
    description:
      - true if the template supports the sshkey upload feature.
    required: false
    default: false
    aliases: []
  isrouting:
    description:
      -  true if the template type is routing i.e., if template is used to deploy router.
    required: false
    default: false
    aliases: []
  format:
    description: 
      - the format for the template.
    required: true
    default: null
    aliases: []
  isextractable:
    description:
      - true if the template or its derivatives are extractable.
    required: false
    default: false
    aliases: []
  details:
    description:
      - Template details in key/value pairs.
    required: false
    default: null
    aliases: []
  bits:
    description:
      - 32 or 64 bits support.
    required: false
    default: '64'
    aliases: []
  displaytext:
    description:
      - the display text of the template.
    required: true
    default: null
    aliases: []
  state:
    description:
      - State of the template.
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
author: Dong Xie 
requirements: [ 'cs' ]
'''

EXAMPLES = '''
---
'''

import sys

try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print("failed=True " + \
        "msg='python library cs required. pip install cs'")
    sys.exit(1)


def get_project_id(module, cs):
    project = module.params.get('project')
    if not project:
        return None

    projects = cs.listProjects()
    if projects:
        for p in projects['project']:
            if p['name'] == project or p['displaytext'] == project or p['id'] == project:
                return p['id']
    module.fail_json(msg="project '%s' not found" % project)


def get_zone_id(module, cs):
    zone = module.params.get('zone')
    zones = cs.listZones()

    if not zone:
        return zones['zone'][0]['id']

    if zones:
        for z in zones['zone']:
            if z['name'] == zone or z['id'] == zone:
                return z['id']
    module.fail_json(msg="zone '%s' not found" % zone)


def get_os_type_id(module, cs):
    os_type = module.params.get('os_type')
    if not os_type:
        return None

    os_types = cs.listOsTypes()
    if os_types:
        for o in os_types['ostype']:
            if o['description'] == os_type or o['id'] == os_type:
                return o['id']
    module.fail_json(msg="OS type '%s' not found" % os_type)

def register_template(module, cs, result, template, zone_id, project_id):
    if not template:
        args = {}
        if project_id:
           args['projectid'] = project_id

        if not zone_id:
            module.fail_json(msg="Zone is requried.")
        args['zoneid'] = zone_id

        args['ostypeid'] = get_os_type_id(module, cs)

        args['url'] = module.params.get('url')
        if not args['url']:
            module.fail_json(msg="URL is requried.")

        args['name'] = module.params.get('name')
        args['displaytext'] = module.params.get('displaytext')
        args['checksum'] = module.params.get('checksum')
        args['isdynamicallyscalable'] = module.params.get('is_dynamically_scalable')
        args['isfeatured'] = module.params.get('is_featured')
        args['ispublic'] = module.params.get('is_public')
        args['format'] = module.params.get('format')
        args['hypervisor'] = module.params.get('hypervisor')

        result['changed'] = True
        if not module.check_mode:
            template = cs.registerTemplate(**args)
    return (result, template)

def get_template(module, cs, zone_id, project_id):
    args = {}
    args['isready'] = module.params.get('is_ready')
    args['templatefilter'] = module.params.get('templatefilter')
    if project_id:
        args['projectid'] = project_id
    if zone_id:
        args['zoneid'] = zone_id

    # if checksum is set, we only look on that.
    checksum = module.params.get('checksum')
    if not checksum:
        args['name'] = module.params.get('name')

    templates = cs.listTemplates(**args)
    if templates:
        # if checksum is set, we only look on that.
        if not checksum:
            return templates['template'][0]
        else:
            for i in templates['template']:
                if i['checksum'] == checksum:
                    return i
    return None


def remove_template(module, cs, result, template, zone_id):
    if template:
        result['changed'] = True
        args = {}
        args['id'] = template['id']
        args['zoneid'] = zone_id
        if not module.check_mode:
            res = cs.deleteTemplate(**args)
    return (result, template)


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True, default=None),
            url = dict(required=True, default=None),
            os_type = dict(required=True, default=None),
            is_ready = dict(choices=BOOLEANS, default=False),
            is_public = dict(choices=BOOLEANS, default=True),
            is_featured = dict(choices=BOOLEANS, default=False),
            is_dynamically_scalable = dict(choices=BOOLEANS, default=False),
            checksum = dict(default=None),
            project = dict(default=None),
            zone = dict(required=True, default=None),
            templatefilter = dict(default='self', choices=[ 'featured', 'self', 'selfexecutable','sharedexecutable','executable', 'community' ]),
            hypervisor = dict(required=True, default=None),
            requireshvm = dict(choices=BOOLEANS, default=False),
            passwordenabled = dict(choices=BOOLEANS, default=False),
            templatetag = dict(default=None),
            sshkeyenabled = dict(choices=BOOLEANS, default=None),
            isrouting = dict(choices=BOOLEANS, default=False),
            format = dict(required=True, default=None),
            isextractable = dict(choices=BOOLEANS, default=False),
            details = dict(default=None),
            bits = dict(default=64, choices=[ 32, 64 ]),
            displaytext = dict(required=True, default=None),
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

        zone_id = get_zone_id(module, cs)
        project_id = get_project_id(module, cs)
        template = get_template(module, cs, zone_id, project_id)

        if state in ['absent']:
            (result, template) = remove_template(module, cs, result, template, zone_id)
        else:
            (result, template) = register_template(module, cs, result, template, zone_id, project_id)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    if template:
        if 'displaytext' in template:
            result['displaytext'] = template['displaytext']
        if 'name' in template:
            result['name'] = template['name']
        if 'zonename' in template:
            result['zone'] = template['zonename']
        if 'checksum' in template:
            result['checksum'] = template['checksum']
        if 'status' in template:
            result['status'] = template['status']

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()

