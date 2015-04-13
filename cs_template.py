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
module: cs_template
short_description: Manages template on Apache CloudStack based clouds.
description: Register from url, create from VM and delete templates.
version_added: '2.0'
author: René Moser
options:
  name:
    description:
      - Name of the Template.
    required: true
  url:
    description:
      - URL of where the template is hosted. Mutually exclusive with C(vm).
    required: false
    default: null
  vm:
    description:
      - VM the template is created from. Mutually exclusive with C(url).
    required: false
    default: null
  os_type:
    description:
      - OS Type that best represents the OS of this template.
    required: false
    default: null
  checksum:
    description:
      - The MD5 checksum value of this template. If set, we search by checksum instead of name.
    required: false
    default: false
  is_ready:
    description:
      - This flag is used for searching existing templates. If set to C(true), it will only list template ready for deployment e.g. successfully downloaded and installed. Recommended to set it to C(false).
    required: false
    default: false
  is_public:
    description:
      - Register the template to be publicly available to all users. Only used if C(state) is present.
    required: false
    default: false
  is_featured:
    description:
      - Register the template to be featured. Only used if C(state) is present.
    required: false
    default: false
  is_dynamically_scalable:
    description:
      - Register the template having XS/VMWare tools installed in order to support 
        dynamic scaling of VM cpu/memory. Only used if C(state) is present.
    required: false
    default: false
  project:
    description:
      - Name of the project the template to be registered in.
    required: false
    default: null
  zone:
    description:
      - Name of the zone you wish the template to be registered or deleted from. If
        not specified, first found zone will be used.
    required: false
    default: null
  template_filter:
    description:
      - Name of the filter used to search for the template.
    required: false
    default: 'self'
    choices: [ 'featured', 'self', 'selfexecutable','sharedexecutable','executable', 'community' ]
  hypervisor:
    description:
      - the target hypervisor for the template. If no hypervisor is provided, first found is used.
    required: false
  requires_hvm:
    description:
      - true if this template requires HVM.
    required: false
    default: false
  password_enabled:
    description:
      - true if the template supports the password reset feature.
    required: false
    default: false
  template_tag:
    description:
      - the tag for this template.
    required: false
    default: null
  sshkey_enabled:
    description:
      - true if the template supports the sshkey upload feature.
    required: false
    default: false
  is_routing:
    description:
      -  true if the template type is routing i.e., if template is used to deploy router. Only considered if C(vm=null).
    required: false
    default: false
  format:
    description: 
      - the format for the template. Required if C(vm=null).
    required: false
    default: null
  is_extractable:
    description:
      - true if the template or its derivatives are extractable.
    required: false
    default: false
  details:
    description:
      - Template details in key/value pairs.
    required: false
    default: null
  bits:
    description:
      - 32 or 64 bits support.
    required: false
    default: '64'
  displaytext:
    description:
      - the display text of the template.
    required: true
    default: null
  state:
    description:
      - State of the template.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
'''

EXAMPLES = '''
---
'''

RETURN = '''
---
name:
  description: Name of the template.
  returned: success
  type: string
  sample: Debian 7 64-bit
displaytext:
  description: Text to be displayed of the template.
  returned: success
  type: string
  sample: Debian 7.7 64-bit minimal 2015-03-19
zone:
  description: Name of zone the template is registered in.
  returned: success
  type: string
  sample: zuerich
checksum:
  description: MD5 checksum of the template.
  returned: success
  type: string
  sample: 0b31bccccb048d20b551f70830bb7ad0
status:
  description: Status of the template.
  returned: success
  type: string
  sample: Successfully Installed
is_ready:
  description: True if the template is ready to be deployed from.
  returned: success
  type: boolean
  sample: true
created:
  description: Date of registering.
  returned: success
  type: string
  sample: 2015-03-29T14:57:06+0200
'''

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

# import cloudstack common
#from ansible.module_utils.cloudstack import *


class AnsibleCloudStackTemplate(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)
        self.result = {
            'changed': False,
        }


    def _get_template_args(self, args):
            args = {}
            args['displaytext'] = self.module.params.get('displaytext')
            args['name'] = self.module.params.get('name')
            args['ostypeid'] = self.get_os_type_id()
            args['bits'] = self.module.params.get('bits')
            args['isdynamicallyscalable'] = self.module.params.get('is_dynamically_scalable')
            args['isextractable'] = self.module.params.get('isextractable')
            args['isfeatured'] = self.module.params.get('is_featured')
            args['ispublic'] = self.module.params.get('is_public')
            args['passwordenabled'] = self.module.params.get('password_enabled')
            args['requireshvm'] = self.module.params.get('requires_hvm')
            args['templatetag'] = self.module.params.get('template_tag')
        return args


    def get_vm(self):
        vm = self.module.params.get('vm')
        if not vm:
            self.module.fail_json(msg="Virtual machine param 'vm' is required")

        args = {}
        args['projectid'] = self.get_project_id()
        vms = self.cs.listVirtualMachines(**args)
        if vms:
            for v in vms['virtualmachine']:
                if vm in [ v['displayname'], v['name'], v['id'] ]:
                    return vm
        self.module.fail_json(msg="Virtual machine '%s' not found" % vm


    def create_template(self):
        template = self.get_template()
        if not template:
            self.result['changed'] = True
            args = self._get_template_args(args)
            vm = self.get_vm()
            args['volumeid'] = vm['rootdeviceid']
            if not self.module.check_mode:
                template = self.cs.createTemplate(**args)
        return template


    def register_template(self):
        template = self.get_template()
        if not template:
            self.result['changed'] = True
            args = self._get_template_args(args)
            args['url'] = self.module.params.get('url')
            if not args['url']:
                self.module.fail_json(msg="URL is requried.")
            args['format'] = self.module.params.get('format')
            if not args['format']:
                self.module.fail_json(msg="Format is requried.")
            args['projectid'] = self.get_project_id()
            args['zoneid'] = self.get_zone_id()
            args['hypervisor'] = self.get_hypervisor()
            args['checksum'] = self.module.params.get('checksum')
            args['isextractable'] = self.module.params.get('is_extractable')
            args['isrouting'] = self.module.params.get('is_routing')
            args['sshkeyenabled'] = self.module.params.get('sshkey_enabled')
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


    def remove_template(self):
        template = self.get_template()
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
            if 'status' in template:
                result['status'] = template['status']
            if 'created' in template:
                result['created'] = template['created']
            if 'templatetag' in template:
                result['template_tag'] = template['templatetag']
        return self.result


def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True),
            url = dict(default=None),
            vm = dict(default=None),
            os_type = dict(required=True),
            is_ready = dict(choices=BOOLEANS, default=False),
            is_public = dict(choices=BOOLEANS, default=True),
            is_featured = dict(choices=BOOLEANS, default=False),
            is_dynamically_scalable = dict(choices=BOOLEANS, default=False),
            checksum = dict(default=None),
            project = dict(default=None),
            zone = dict(default=None),
            template_filter = dict(default='self', choices=[ 'featured', 'self', 'selfexecutable','sharedexecutable','executable', 'community' ]),
            hypervisor = dict(default=None),
            requires_hvm = dict(choices=BOOLEANS, default=False),
            password_enabled = dict(choices=BOOLEANS, default=False),
            template_tag = dict(default=None),
            sshkey_enabled = dict(choices=BOOLEANS, default=None),
            is_routing = dict(choices=BOOLEANS, default=False),
            format = dict(default=None, choices=['QCOW2', 'RAW', 'VHD']),
            is_extractable = dict(choices=BOOLEANS, default=False),
            details = dict(default=None),
            bits = dict(default=64, choices=[ 32, 64 ]),
            displaytext = dict(required=True),
            state = dict(choices=['present', 'absent'], default='present'),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
        ),
        mutually_exclusive = (
            ['url', 'vm'],
        ),
        required_together = (
            ['vm', 'format'],
        ),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_tpl = AnsibleCloudStackTemplate(module)

        state = module.params.get('state')
        if state in ['absent']:
            tpl = acs_tpl.remove_template()
        else:
            vm = module.params.get('vm')
            if vm:
                tpl = acs_tpl.create_template()
            else:
                tpl = acs_tpl.register_template()

        result = acs_tpl.get_result(tpl)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
