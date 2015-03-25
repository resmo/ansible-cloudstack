#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015, Dong Xie <dong.xie@interoute.com>
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
  template_filter:
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
  requires_hvm:
    description:
      - true if this template requires HVM.
    required: false
    default: false
    aliases: []
  password_enabled:
    description:
      - true if the template supports the password reset feature.
    required: false
    default: false
    aliases: []
  template_tag:
    description:
      - the tag for this template.
    required: false
    default: null
    aliases: []
  sshkey_enabled:
    description:
      - true if the template supports the sshkey upload feature.
    required: false
    default: false
    aliases: []
  is_routing:
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
  is_extractable:
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
author: Dong Xie, René Moser
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


class AnsibleCloudStack:

    def __init__(self, module):
        self.module = module
        self._connect()

        self.project_id = None
        self.ip_address_id = None
        self.zone_id = None
        self.vm_id = None
        self.os_type_id = None
        self.hypervisor = None


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
                    self.project_id = p['id']
                    return self.project_id
        self.module.fail_json(msg="project '%s' not found" % project)


    def get_ip_address_id(self):
        if self.ip_address_id:
            return self.ip_address_id

        ip_address = self.module.params.get('ip_address')
        if not ip_address:
            self.module.fail_json(msg="IP address param 'ip_address' is required")

        args = {}
        args['ipaddress'] = ip_address
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
        if not vm:
            self.module.fail_json(msg="Virtual machine param 'vm' is required")

        args = {}
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


    def get_hypervisor(self):
        if self.hypervisor:
            return self.hypervisor

        hypervisor = self.module.params.get('hypervisor')
        hypervisors = self.cs.listHypervisors()

        if not hypervisor:
            return hypervisors['hypervisor'][0]['name']

        for h in hypervisors['hypervisor']:
            if hypervisor.lower() == h['name'].lower():
                self.hypervisor = h['name']
                return self.hypervisor
        self.module.fail_json(msg="Hypervisor '%s' not found" % hypervisor)


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


class AnsibleCloudStackTemplate(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)
        self.result = {
            'changed': False,
        }


    def register_template(self, template):
        if not template:
            args = {}
            args['projectid'] = self.get_project_id()
            args['zoneid'] = self.get_zone_id()
            args['ostypeid'] = self.get_os_type_id()
            args['hypervisor'] = self.get_hypervisor()

            args['url'] = self.smodule.params.get('url')
            if not args['url']:
                self.module.fail_json(msg="URL is requried.")

            args['name'] = self.module.params.get('name')
            args['displaytext'] = self.module.params.get('displaytext')
            args['bits'] = self.module.params.get('bits')
            args['checksum'] = self.module.params.get('checksum')
            args['isdynamicallyscalable'] = self.module.params.get('is_dynamically_scalable')
            args['isextractable'] = self.module.params.get('isextractable')
            args['isfeatured'] = self.module.params.get('is_featured')
            args['ispublic'] = self.module.params.get('is_public')
            args['format'] = self.module.params.get('format')
            args['isrouting'] = self.module.params.get('is_routing')
            args['passwordenabled'] = self.module.params.get('password_enabled')
            args['requireshvm'] = self.module.params.get('requires_hvm')
            args['sshkeyenabled'] = self.module.params.get('sshkey_enabled')
            args['templatetag'] = self.module.params.get('template_tag')

            self.result['changed'] = True
            if not self.module.check_mode:
                template = self.cs.registerTemplate(**args)
        return template


    def get_template(self):
        args = {}
        args['isready'] = self.module.params.get('is_ready')
        args['projectid'] = self.get_project_id()
        args['zoneid'] = self.get_zone_id()
        args['templatefilter'] = self.module.params.get('template_filter')

        # if checksum is set, we only look on that.
        checksum = self.module.params.get('checksum')
        if not checksum:
            args['name'] = self.module.params.get('name')

        templates = self.cs.listTemplates(**args)
        if templates:
            # if checksum is set, we only look on that.
            if not checksum:
                return templates['template'][0]
            else:
                for i in templates['template']:
                    if i['checksum'] == checksum:
                        return i
        return None


    def remove_template(self, template):
        if template:
            self.result['changed'] = True
            args = {}
            args['id'] = template['id']
            args['zoneid'] = self.get_zone_id()
            if not self.module.check_mode:
                res = self.cs.deleteTemplate(**args)
        return template


    def get_result(self, template):
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
            if 'created' in template:
                result['created'] = template['created']
        return self.result


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
            template_filter = dict(default='self', choices=[ 'featured', 'self', 'selfexecutable','sharedexecutable','executable', 'community' ]),
            hypervisor = dict(required=True, default=None),
            requires_hvm = dict(choices=BOOLEANS, default=False),
            password_enabled = dict(choices=BOOLEANS, default=False),
            template_tag = dict(default=None),
            sshkey_enabled = dict(choices=BOOLEANS, default=None),
            is_routing = dict(choices=BOOLEANS, default=False),
            format = dict(required=True, default=None),
            is_extractable = dict(choices=BOOLEANS, default=False),
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

    try:
        acs_tpl = AnsibleCloudStackTemplate(module)
        tpl = acs_tpl.get_template()

        state = module.params.get('state')
        if state in ['absent']:
            tpl = acs_tpl.remove_template(tpl)
        else:
            tpl = acs_tpl.register_iso(tpl)

        result = acs_tpl.get_result(tpl)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
