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
module: cs_user
short_description: Manages users on Apache CloudStack based clouds.
description:
    - Create, update, disable, lock, enable and remove users.
version_added: '2.0'
author: "René Moser (@resmo)"
options:
  username:
    description:
      - Username of the user.
    required: true
  account:
    description:
      - Account the user will be created under.
      - Required on C(state=present).
    required: false
    default: null
  password:
    description:
      - Password of the user to be created.
      - Required on C(state=present).
      - Only considered on creation and will not be updated if user exists.
    required: false
    default: null
  first_name:
    description:
      - First name of the user.
      - Required on C(state=present).
    required: false
    default: null
  last_name:
    description:
      - Last name of the user.
      - Required on C(state=present).
    required: false
    default: null
  email:
    description:
      - Email of the user.
      - Required on C(state=present).
    required: false
    default: null
  timezone:
    description:
      - Timezone of the user.
    required: false
    default: null
  domain:
    description:
      - Domain the user is related to.
    required: false
    default: 'ROOT'
  state:
    description:
      - State of the user.
      - C(unlocked) is an alias for C(enabled).
    required: false
    default: 'present'
    choices: [ 'present', 'absent', 'enabled', 'disabled', 'locked', 'unlocked' ]
  poll_async:
    description:
      - Poll async jobs until job has finished.
    required: false
    default: true
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
# create an user in domain 'CUSTOMERS'
local_action:
  module: cs_user
  account: developers
  username: johndoe
  password: S3Cur3
  last_name: Doe
  first_name: John
  email: john.doe@example.com
  domain: CUSTOMERS

# Lock an existing user in domain 'CUSTOMERS'
local_action:
  module: cs_user
  username: johndoe
  domain: CUSTOMERS
  state: locked

# Disable an existing user in domain 'CUSTOMERS'
local_action:
  module: cs_user
  username: johndoe
  domain: CUSTOMERS
  state: disabled

# Enable/unlock an existing user in domain 'CUSTOMERS'
local_action:
  module: cs_user
  username: johndoe
  domain: CUSTOMERS
  state: enabled

# Remove an user in domain 'CUSTOMERS'
local_action:
  module: cs_user
  name: customer_xy
  domain: CUSTOMERS
  state: absent
'''

RETURN = '''
---
id:
  description: UUID of the user.
  returned: success
  type: string
  sample: 87b1e0ce-4e01-11e4-bb66-0050569e64b8
username:
  description: Username of the user.
  returned: success
  type: string
  sample: johndoe
fist_name:
  description: First name of the user.
  returned: success
  type: string
  sample: John
last_name:
  description: Last name of the user.
  returned: success
  type: string
  sample: Doe
email:
  description: Emailof the user.
  returned: success
  type: string
  sample: john.doe@example.com
api_key:
  description: API key of the user.
  returned: success
  type: string
  sample: JLhcg8VWi8DoFqL2sSLZMXmGojcLnFrOBTipvBHJjySODcV4mCOo29W2duzPv5cALaZnXj5QxDx3xQfaQt3DKg
api_secret:
  description: API secret of the user.
  returned: success
  type: string
  sample: FUELo3LB9fa1UopjTLPdqLv_6OXQMJZv9g9N4B_Ao3HFz8d6IGFCV9MbPFNM8mwz00wbMevja1DoUNDvI8C9-g
account:
  description: Account name of the user.
  returned: success
  type: string
  sample: developers
account_type:
  description: Type of the account.
  returned: success
  type: string
  sample: user
timezone:
  description: Timezone of the user.
  returned: success
  type: string
  sample: enabled
created:
  description: Date the user was created.
  returned: success
  type: string
  sample: Doe
state:
  description: State of the user.
  returned: success
  type: string
  sample: enabled
domain:
  description: Domain the user is related.
  returned: success
  type: string
  sample: ROOT
'''

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

# import cloudstack common
CS_HYPERVISORS=[
    'KVM', 'kvm',
    'VMware', 'vmware',
    'BareMetal', 'baremetal',
    'XenServer', 'xenserver',
    'LXC', 'lxc',
    'HyperV', 'hyperv',
    'UCS', 'ucs',
    'OVM', 'ovm',
    'Simulator', 'simulator',
    ]

def cs_argument_spec():
    return dict(
        api_key = dict(default=None),
        api_secret = dict(default=None, no_log=True),
        api_url = dict(default=None),
        api_http_method = dict(choices=['get', 'post'], default='get'),
        api_timeout = dict(type='int', default=10),
        api_region = dict(default='cloudstack'),
    )

def cs_required_together():
    return [['api_key', 'api_secret', 'api_url']]

class AnsibleCloudStack(object):

    def __init__(self, module):
        if not has_lib_cs:
            module.fail_json(msg="python library cs required: pip install cs")

        self.result = {
            'changed': False,
        }

        # Common returns, will be merged with self.returns
        # search_for_key: replace_with_key
        self.common_returns = {
            'id':           'id',
            'name':         'name',
            'created':      'created',
            'zonename':     'zone',
            'state':        'state',
            'project':      'project',
            'account':      'account',
            'domain':       'domain',
            'displaytext':  'display_text',
            'displayname':  'display_name',
            'description':  'description',
        }

        # Init returns dict for use in subclasses
        self.returns = {}
        # these values will be casted to int
        self.returns_to_int = {}

        self.module = module
        self._connect()

        self.domain = None
        self.account = None
        self.project = None
        self.ip_address = None
        self.zone = None
        self.vm = None
        self.os_type = None
        self.hypervisor = None
        self.capabilities = None
        self.tags = None


    def _connect(self):
        api_key = self.module.params.get('api_key')
        api_secret = self.module.params.get('secret_key')
        api_url = self.module.params.get('api_url')
        api_http_method = self.module.params.get('api_http_method')
        api_timeout = self.module.params.get('api_timeout')

        if api_key and api_secret and api_url:
            self.cs = CloudStack(
                endpoint=api_url,
                key=api_key,
                secret=api_secret,
                timeout=api_timeout,
                method=api_http_method
                )
        else:
            api_region = self.module.params.get('api_region', 'cloudstack')
            self.cs = CloudStack(**read_config(api_region))


    def get_or_fallback(self, key=None, fallback_key=None):
        value = self.module.params.get(key)
        if not value:
            value = self.module.params.get(fallback_key)
        return value


    def fail_on_missing_params(self, required_params=None):
        if not required_params:
            return
        missing_params = []
        for required_param in required_params:
            if not self.module.params.get(required_param):
                missing_params.append(required_param)
        if missing_params:
            self.module.fail_json(msg="missing required arguments: %s" % ','.join(missing_params))


    # TODO: for backward compatibility only, remove if not used anymore
    def _has_changed(self, want_dict, current_dict, only_keys=None):
        return self.has_changed(want_dict=want_dict, current_dict=current_dict, only_keys=only_keys)


    def has_changed(self, want_dict, current_dict, only_keys=None):
        for key, value in want_dict.iteritems():
            # Optionally limit by a list of keys
            if only_keys and key not in only_keys:
                continue
            # Skip None values
            if value is None:
                continue

            if key in current_dict:
                # API returns string for int in some cases, just to make sure
                if isinstance(value, (int, long, float, complex)):
                    current_dict[key] = int(current_dict[key])
                    if value != current_dict[key]:
                        return True
                elif isinstance(value, str):
                    current_dict[key] = str(current_dict[key])
                    # Test for diff in case insensitive way
                    if value.lower() != current_dict[key].lower():
                        return True
                else:
                    current_dict[key] = str(current_dict[key])
                    if value != current_dict[key]:
                        return True
        return False


    def _get_by_key(self, key=None, my_dict=None):
        if my_dict is None:
            my_dict = {}
        if key:
            if key in my_dict:
                return my_dict[key]
            self.module.fail_json(msg="Something went wrong: %s not found" % key)
        return my_dict


    def get_project(self, key=None):
        if self.project:
            return self._get_by_key(key, self.project)

        project = self.module.params.get('project')
        if not project:
            return None
        args = {}
        args['account'] = self.get_account(key='name')
        args['domainid'] = self.get_domain(key='id')
        projects = self.cs.listProjects(**args)
        if projects:
            for p in projects['project']:
                if project.lower() in [ p['name'].lower(), p['id'] ]:
                    self.project = p
                    return self._get_by_key(key, self.project)
        self.module.fail_json(msg="project '%s' not found" % project)


    def get_ip_address(self, key=None):
        if self.ip_address:
            return self._get_by_key(key, self.ip_address)

        ip_address = self.module.params.get('ip_address')
        if not ip_address:
            self.module.fail_json(msg="IP address param 'ip_address' is required")

        args = {}
        args['ipaddress'] = ip_address
        args['account'] = self.get_account(key='name')
        args['domainid'] = self.get_domain(key='id')
        args['projectid'] = self.get_project(key='id')
        ip_addresses = self.cs.listPublicIpAddresses(**args)

        if not ip_addresses:
            self.module.fail_json(msg="IP address '%s' not found" % args['ipaddress'])

        self.ip_address = ip_addresses['publicipaddress'][0]
        return self._get_by_key(key, self.ip_address)


    def get_vm(self, key=None):
        if self.vm:
            return self._get_by_key(key, self.vm)

        vm = self.module.params.get('vm')
        if not vm:
            self.module.fail_json(msg="Virtual machine param 'vm' is required")

        args = {}
        args['account'] = self.get_account(key='name')
        args['domainid'] = self.get_domain(key='id')
        args['projectid'] = self.get_project(key='id')
        args['zoneid'] = self.get_zone(key='id')
        vms = self.cs.listVirtualMachines(**args)
        if vms:
            for v in vms['virtualmachine']:
                if vm.lower() in [ v['name'].lower(), v['displayname'].lower(), v['id'] ]:
                    self.vm = v
                    return self._get_by_key(key, self.vm)
        self.module.fail_json(msg="Virtual machine '%s' not found" % vm)


    def get_zone(self, key=None):
        if self.zone:
            return self._get_by_key(key, self.zone)

        zone = self.module.params.get('zone')
        zones = self.cs.listZones(name=zone)

        # use the first zone if no zone param given
        if zones:
            self.zone = zones['zone'][0]
            return self._get_by_key(key, self.zone)
        self.module.fail_json(msg="No zones found")


    def get_os_type(self, key=None):
        if self.os_type:
            return self._get_by_key(key, self.zone)

        os_type = self.module.params.get('os_type')
        if not os_type:
            return None

        os_types = self.cs.listOsTypes()
        if os_types:
            for o in os_types['ostype']:
                if os_type in [ o['description'], o['id'] ]:
                    self.os_type = o
                    return self._get_by_key(key, self.os_type)
        self.module.fail_json(msg="OS type '%s' not found" % os_type)


    def get_hypervisor(self):
        if self.hypervisor:
            return self.hypervisor

        hypervisor = self.module.params.get('hypervisor')
        hypervisors = self.cs.listHypervisors()

        # use the first hypervisor if no hypervisor param given
        if not hypervisor:
            self.hypervisor = hypervisors['hypervisor'][0]['name']
            return self.hypervisor

        for h in hypervisors['hypervisor']:
            if hypervisor.lower() == h['name'].lower():
                self.hypervisor = h['name']
                return self.hypervisor
        self.module.fail_json(msg="Hypervisor '%s' not found" % hypervisor)


    def get_account(self, key=None):
        if self.account:
            return self._get_by_key(key, self.account)

        account = self.module.params.get('account')
        if not account:
            return None

        domain = self.module.params.get('domain')
        if not domain:
            self.module.fail_json(msg="Account must be specified with Domain")

        args = {}
        args['name'] = account
        args['domainid'] = self.get_domain(key='id')
        args['listall'] = True
        accounts = self.cs.listAccounts(**args)
        if accounts:
            self.account = accounts['account'][0]
            return self._get_by_key(key, self.account)
        self.module.fail_json(msg="Account '%s' not found" % account)


    def get_domain(self, key=None):
        if self.domain:
            return self._get_by_key(key, self.domain)

        domain = self.module.params.get('domain')
        if not domain:
            return None

        args = {}
        args['listall'] = True
        domains = self.cs.listDomains(**args)
        if domains:
            for d in domains['domain']:
                if d['path'].lower() in [ domain.lower(), "root/" + domain.lower(), "root" + domain.lower() ]:
                    self.domain = d
                    return self._get_by_key(key, self.domain)
        self.module.fail_json(msg="Domain '%s' not found" % domain)


    def get_tags(self, resource=None):
        if not self.tags:
            args = {}
            args['projectid'] = self.get_project(key='id')
            args['account'] = self.get_account(key='name')
            args['domainid'] = self.get_domain(key='id')
            args['resourceid'] = resource['id']
            response = self.cs.listTags(**args)
            self.tags = response.get('tag', [])

        existing_tags = []
        if self.tags:
            for tag in self.tags:
                existing_tags.append({'key': tag['key'], 'value': tag['value']})
        return existing_tags


    def _process_tags(self, resource, resource_type, tags, operation="create"):
        if tags:
            self.result['changed'] = True
            if not self.module.check_mode:
                args = {}
                args['resourceids']  = resource['id']
                args['resourcetype'] = resource_type
                args['tags']         = tags
                if operation == "create":
                    response = self.cs.createTags(**args)
                else:
                    response = self.cs.deleteTags(**args)
                self.poll_job(response)


    def _tags_that_should_exist_or_be_updated(self, resource, tags):
        existing_tags = self.get_tags(resource)
        return [tag for tag in tags if tag not in existing_tags]


    def _tags_that_should_not_exist(self, resource, tags):
        existing_tags = self.get_tags(resource)
        return [tag for tag in existing_tags if tag not in tags]


    def ensure_tags(self, resource, resource_type=None):
        if not resource_type or not resource:
            self.module.fail_json(msg="Error: Missing resource or resource_type for tags.")

        if 'tags' in resource:
            tags = self.module.params.get('tags')
            if tags is not None:
                self._process_tags(resource, resource_type, self._tags_that_should_not_exist(resource, tags), operation="delete")
                self._process_tags(resource, resource_type, self._tags_that_should_exist_or_be_updated(resource, tags))
                self.tags = None
                resource['tags'] = self.get_tags(resource)
        return resource


    def get_capabilities(self, key=None):
        if self.capabilities:
            return self._get_by_key(key, self.capabilities)
        capabilities = self.cs.listCapabilities()
        self.capabilities = capabilities['capability']
        return self._get_by_key(key, self.capabilities)


    # TODO: for backward compatibility only, remove if not used anymore
    def _poll_job(self, job=None, key=None):
        return self.poll_job(job=job, key=key)


    def poll_job(self, job=None, key=None):
        if 'jobid' in job:
            while True:
                res = self.cs.queryAsyncJobResult(jobid=job['jobid'])
                if res['jobstatus'] != 0 and 'jobresult' in res:
                    if 'errortext' in res['jobresult']:
                        self.module.fail_json(msg="Failed: '%s'" % res['jobresult']['errortext'])
                    if key and key in res['jobresult']:
                        job = res['jobresult'][key]
                    break
                time.sleep(2)
        return job


    def get_result(self, resource):
        if resource:
            returns = self.common_returns.copy()
            returns.update(self.returns)
            for search_key, return_key in returns.iteritems():
                if search_key in resource:
                    self.result[return_key] = resource[search_key]

            # Bad bad API does not always return int when it should.
            for search_key, return_key in self.returns_to_int.iteritems():
                if search_key in resource:
                    self.result[return_key] = int(resource[search_key])

            # Special handling for tags
            if 'tags' in resource:
                self.result['tags'] = []
                for tag in resource['tags']:
                    result_tag          = {}
                    result_tag['key']   = tag['key']
                    result_tag['value'] = tag['value']
                    self.result['tags'].append(result_tag)
        return self.result


class AnsibleCloudStackUser(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackUser, self).__init__(module)
        self.returns = {
            'username':     'username',
            'firstname':    'first_name',
            'lastname':     'last_name',
            'email':        'email',
            'secretkey':    'api_secret',
            'apikey':       'api_key',
            'timezone':     'timezone',
        }
        self.account_types = {
            'user':         0,
            'root_admin':   1,
            'domain_admin': 2,
        }
        self.user = None


    def get_account_type(self):
        account_type = self.module.params.get('account_type')
        return self.account_types[account_type]


    def get_user(self):
        if not self.user:
            args                = {}
            args['domainid']    = self.get_domain('id')
            users = self.cs.listUsers(**args)
            if users:
                user_name = self.module.params.get('username')
                for u in users['user']:
                    if user_name.lower() == u['username'].lower():
                        self.user = u
                        break
        return self.user


    def enable_user(self):
        user = self.get_user()
        if not user:
            user = self.present_user()

        if user['state'].lower() != 'enabled':
            self.result['changed'] = True
            args        = {}
            args['id']  = user['id']
            if not self.module.check_mode:
                res = self.cs.enableUser(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                user = res['user']
        return user


    def lock_user(self):
        user = self.get_user()
        if not user:
            user = self.present_user()

        # we need to enable the user to lock it.
        if user['state'].lower() == 'disabled':
            user = self.enable_user()

        if user['state'].lower() != 'locked':
            self.result['changed'] = True
            args        = {}
            args['id']  = user['id']
            if not self.module.check_mode:
                res = self.cs.lockUser(**args)

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                user = res['user']
        return user


    def disable_user(self):
        user = self.get_user()
        if not user:
            user = self.present_user()

        if user['state'].lower() != 'disabled':
            self.result['changed'] = True
            args        = {}
            args['id']  = user['id']
            if not self.module.check_mode:
                user = self.cs.disableUser(**args)
                if 'errortext' in user:
                    self.module.fail_json(msg="Failed: '%s'" % user['errortext'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    user = self._poll_job(user, 'user')
        return user


    def present_user(self):
        missing_params = []
        for required_params in [
            'account',
            'email',
            'password',
            'first_name',
            'last_name',
        ]:
            if not self.module.params.get(required_params):
                missing_params.append(required_params)
        if missing_params:
            self.module.fail_json(msg="missing required arguments: %s" % ','.join(missing_params))

        user = self.get_user()
        if user:
            user = self._update_user(user)
        else:
            user = self._create_user(user)
        return user


    def _create_user(self, user):
        self.result['changed'] = True

        args                = {}
        args['account']     = self.get_account(key='name')
        args['domainid']    = self.get_domain('id')
        args['username']    = self.module.params.get('username')
        args['password']    = self.module.params.get('password')
        args['firstname']   = self.module.params.get('first_name')
        args['lastname']    = self.module.params.get('last_name')
        args['email']       = self.module.params.get('email')
        args['timezone']    = self.module.params.get('timezone')
        if not self.module.check_mode:
            res = self.cs.createUser(**args)
            if 'errortext' in res:
                self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
            user = res['user']
            # register user api keys
            res = self.cs.registerUserKeys(id=user['id'])
            if 'errortext' in res:
                self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
            user.update(res['userkeys'])
        return user


    def _update_user(self, user):
        args                = {}
        args['id']          = user['id']
        args['firstname']   = self.module.params.get('first_name')
        args['lastname']    = self.module.params.get('last_name')
        args['email']       = self.module.params.get('email')
        args['timezone']    = self.module.params.get('timezone')
        if self.has_changed(args, user):
            self.result['changed'] = True
            if not self.module.check_mode:
                res = self.cs.updateUser(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                user = res['user']
        # register user api keys
        if 'apikey' not in user:
            self.result['changed'] = True
            if not self.module.check_mode:
                res = self.cs.registerUserKeys(id=user['id'])
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                user.update(res['userkeys'])
        return user


    def absent_user(self):
        user = self.get_user()
        if user:
            self.result['changed'] = True

            if not self.module.check_mode:
                res = self.cs.deleteUser(id=user['id'])

                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
        return user


    def get_result(self, user):
        super(AnsibleCloudStackUser, self).get_result(user)
        if user:
            if 'accounttype' in user:
                for key,value in self.account_types.items():
                    if value == user['accounttype']:
                        self.result['account_type'] = key
                        break
        return self.result


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        username = dict(required=True),
        account = dict(default=None),
        state = dict(choices=['present', 'absent', 'enabled', 'disabled', 'locked', 'unlocked'], default='present'),
        domain = dict(default='ROOT'),
        email = dict(default=None),
        first_name = dict(default=None),
        last_name = dict(default=None),
        password = dict(default=None),
        timezone = dict(default=None),
        poll_async = dict(type='bool', default=True),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=cs_required_together(),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_acc = AnsibleCloudStackUser(module)

        state = module.params.get('state')

        if state in ['absent']:
            user = acs_acc.absent_user()

        elif state in ['enabled', 'unlocked']:
            user = acs_acc.enable_user()

        elif state in ['disabled']:
            user = acs_acc.disable_user()

        elif state in ['locked']:
            user = acs_acc.lock_user()

        else:
            user = acs_acc.present_user()

        result = acs_acc.get_result(user)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
