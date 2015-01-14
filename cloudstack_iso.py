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
module: cloudstack_iso
short_description: Register and delete ISOs on Apache CloudStack based clouds.
description:
    - Manage ISOs on Apache CloudStack, Citrix CloudPlatform and Exoscale.
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), see https://github.com/exoscale/cs on which this module depends on.
    - This module supports check mode.
version_added: '1.9'
options:
  name:
    description:
      - Name of the ISO.
    required: true
    default: null
    aliases: []
  url:
    description:
      - URL where the ISO can be downloaded from. Required if C(state) is present.
    required: false
    default: null
    aliases: []
  os_type:
    description:
      - Name of the OS that best represents the OS of this ISO. If the iso is bootable this parameter needs to be passed. Required if C(state) is present.
    required: false
    default: null
    aliases: []
  is_ready:
    description:
      - This flag is used for searching existing ISOs. If set to C(true), it will only list ISO ready for deployment e.g. successfully downloaded and installed. Recommended to set it to C(false).
    required: false
    default: false
    aliases: []
  is_public:
    description:
      - Register the ISO to be publicly available to all users. Only used if C(state) is present.
    required: false
    default: false
    aliases: []
  is_featured:
    description:
      - Register the ISO to be featured. Only used if C(state) is present.
    required: false
    default: false
    aliases: []
  is_dynamically_scalable:
    description:
      - Register the ISO having XS/VMWare tools installed inorder to support 
        dynamic scaling of VM cpu/memory. Only used if C(state) is present.
    required: false
    default: false
    aliases: []
  checksum:
    description:
      - The MD5 checksum value of this ISO. If set, we search by checksum instead of name.
    required: false
    default: false
    aliases: []
  bootable:
    description:
      - Register the ISO to be bootable. Only used if C(state) is present.
    required: false
    default: true
    aliases: []
  project:
    description:
      - Name of the project the ISO to be registered in.
    required: false
    default: null
    aliases: []
  zone:
    description:
      - Name of the zone you wish the ISO to be registered or deleted from. If
        not specified, all zones will be used.
    required: false
    default: null
    aliases: []
  isofilter:
    description:
      - Name of the filter used to search for the ISO.
    required: false
    default: 'self'
    choices: [ 'featured', 'self', 'selfexecutable','sharedexecutable','executable', 'community' ]
    aliases: []
  state:
    description:
      - State of the ISO.
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
author: René Moser
requirements: [ 'cs' ]
'''

EXAMPLES = '''
---
# Register an ISO if ISO name does not already exist.
- cloudstack_iso:
     name: Debian 7 64-bit
     url: http://mirror.switch.ch/ftp/mirror/debian-cd/current/amd64/iso-cd/debian-7.7.0-amd64-netinst.iso
     os_type: Debian GNU/Linux 7(64-bit)


# Register an ISO with given name if ISO md5 checksum does not already exist.
- cloudstack_iso:
     name: Debian 7 64-bit
     url: http://mirror.switch.ch/ftp/mirror/debian-cd/current/amd64/iso-cd/debian-7.7.0-amd64-netinst.iso
     os_type: Debian GNU/Linux 7(64-bit)
     checksum: 0b31bccccb048d20b551f70830bb7ad0


# Remove an ISO by name
# Register an ISO with given name if ISO md5 checksum does not already exist.
- cloudstack_iso:
     name: Debian 7 64-bit
     state: absent


# Remove an ISO by checksum
- cloudstack_iso:
     name: Debian 7 64-bit
     checksum: 0b31bccccb048d20b551f70830bb7ad0
     state: absent
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
        return None

    projects = cs.listProjects()
    if projects:
        for p in projects['project']:
            if p['name'] == project or p['id'] == project:
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


def register_iso(module, cs, result, iso, zone_id, project_id):
    if not iso:
        args = {}
        if project_id:
           args['projectid'] = project_id

        if not zone_id:
            module.fail_json(msg="Zone is requried.")
        args['zoneid'] = zone_id

        args['bootable'] = module.params.get('bootable')
        args['ostypeid'] = get_os_type_id(module, cs)
        if args['bootable'] and not args['ostypeid']:
            module.fail_json(msg="OS type is requried if bootable is true.")

        args['url'] = module.params.get('url')
        if not args['url']:
            module.fail_json(msg="URL is requried.")

        args['name'] = module.params.get('name')
        args['displaytext'] = module.params.get('name')
        args['checksum'] = module.params.get('checksum')
        args['isdynamicallyscalable'] = module.params.get('is_dynamically_scalable')
        args['isfeatured'] = module.params.get('is_featured')
        args['ispublic'] = module.params.get('is_public')

        result['changed'] = True
        if not module.check_mode:
            iso = cs.registerIso(**args)
    return (result, iso)


def get_iso(module, cs, zone_id, project_id):
    args = {}
    args['isready'] = module.params.get('is_ready')
    args['isofilter'] = module.params.get('iso_filter')
    if project_id:
        args['projectid'] = project_id
    if zone_id:
        args['zoneid'] = zone_id

    # if checksum is set, we only look on that.
    checksum = module.params.get('checksum')
    if not checksum:
        args['name'] = module.params.get('name')

    isos = cs.listIsos(**args)
    if isos:
        # if checksum is set, we only look on that.
        if not checksum:
            return isos['iso'][0]
        else:
            for i in isos['iso']:
                if i['checksum'] == checksum:
                    return i
    return None


def remove_iso(module, cs, result, iso, zone_id):
    if iso:
        result['changed'] = True
        args = {}
        args['id'] = iso['id']
        args['zoneid'] = zone_id
        if not module.check_mode:
            res = cs.deleteIso(**args)
    return (result, iso)


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True, default=None),
            url = dict(default=None),
            os_type = dict(default=None),
            zone = dict(default=None),
            isofilter = dict(default='self', choices=[ 'featured', 'self', 'selfexecutable','sharedexecutable','executable', 'community' ]),
            project = dict(default=None),
            checksum = dict(default=None),
            is_ready = dict(choices=BOOLEANS, default=False),
            bootable = dict(choices=BOOLEANS, default=True),
            is_featured = dict(choices=BOOLEANS, default=False),
            is_dynamically_scalable = dict(choices=BOOLEANS, default=False),
            state = dict(choices=['present', 'absent'], default='present'),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
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

        if api_key and api_secret and api_url:
            cs = CloudStack(
                endpoint=api_url,
                key=api_key,
                secret=api_secret
                )
        else:
            cs = CloudStack(**read_config())

        zone_id = get_zone_id(module, cs)
        project_id = get_project_id(module, cs)
        iso = get_iso(module, cs, zone_id, project_id)

        if state in ['absent']:
            (result, iso) = remove_iso(module, cs, result, iso, zone_id)
        else:
            (result, iso) = register_iso(module, cs, result, iso, zone_id, project_id)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    if iso:
        if 'displaytext' in iso:
            result['displaytext'] = iso['displaytext']
        if 'name' in iso:
            result['name'] = iso['name']
        if 'zonename' in iso:
            result['zone'] = iso['zonename']
        if 'checksum' in iso:
            result['checksum'] = iso['checksum']
        if 'status' in iso:
            result['status'] = iso['status']

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
