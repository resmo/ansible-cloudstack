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
    - Credentials can be stored locally in C($HOME/.cloudstack.ini) instead of using C(api_url), C(api_key), C(api_secret), C(api_http_method), see https://github.com/exoscale/cs on which this module depends on.
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
                    self.prject_id = p[id]
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


class AnsibleCloudStackIso(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)


    def register_iso(self, iso):
        if not iso:
            args = {}
            args['zoneid'] = self.get_zone_id()
            args['bootable'] = self.module.params.get('bootable')
            args['ostypeid'] = self.get_os_type_id()
            if args['bootable'] and not args['ostypeid']:
                self.module.fail_json(msg="OS type is requried if bootable is true.")

            args['url'] = self.module.params.get('url')
            if not args['url']:
                self.module.fail_json(msg="URL is requried.")

            args['name'] = self.module.params.get('name')
            args['displaytext'] = self.module.params.get('name')
            args['checksum'] = self.module.params.get('checksum')
            args['isdynamicallyscalable'] = self.module.params.get('is_dynamically_scalable')
            args['isfeatured'] = self.module.params.get('is_featured')
            args['ispublic'] = self.module.params.get('is_public')

            self.result['changed'] = True
            if not self.module.check_mode:
                iso = self.cs.registerIso(**args)
        
        return iso


    def get_iso(self):
        args = {}
        args['isready'] = self.module.params.get('is_ready')
        args['isofilter'] = self.module.params.get('iso_filter')
        args['projectid'] = self.get_project_id()
        args['zoneid'] = self.get_zone_id()

        # if checksum is set, we only look on that.
        checksum = self.module.params.get('checksum')
        if not checksum:
            args['name'] = self.module.params.get('name')

        isos = self.cs.listIsos(**args)
        if isos:
            # if checksum is set, we only look on that.
            if not checksum:
                return isos['iso'][0]
            else:
                for i in isos['iso']:
                    if i['checksum'] == checksum:
                        return i
        return None


    def remove_iso(self, iso):
        if iso:
            self.result['changed'] = True
            args = {}
            args['id'] = iso['id']
            args['zoneid'] = zone_id
            if not self.module.check_mode:
                res = self.cs.deleteIso(**args)
        return iso


    def get_result(self, iso):
        if iso:
            if 'displaytext' in iso:
                self.result['displaytext'] = iso['displaytext']
            if 'name' in iso:
                self.result['name'] = iso['name']
            if 'zonename' in iso:
                self.result['zone'] = iso['zonename']
            if 'checksum' in iso:
                self.result['checksum'] = iso['checksum']
            if 'status' in iso:
                self.result['status'] = iso['status']
        return self.result


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
            api_http_method = dict(default='get'),
        ),
        supports_check_mode=True
    )

    try:
        ansible_cloudstack_iso = AnsibleCloudStackIso(module)
        iso = ansible_cloudstack_iso.get_iso()

        state = module.params.get('state')
        if state in ['absent']:
            iso = ansible_cloudstack_iso.remove_iso(iso)
        else:
            iso = ansible_cloudstack_iso.register_iso(iso)

        result = ansible_cloudstack_iso.get_result(iso)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
