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
module: cs_sshkeypair
short_description: Manages SSH keys on Apache CloudStack based clouds.
description:
    - Create, register and remove SSH keys.
    - If no key was found and no public key was provided and a new SSH
      private/public key pair will be created and the private key will be returned.
version_added: '2.0'
author: "René Moser (@resmo)"
options:
  name:
    description:
      - Name of public key.
    required: true
  domain:
    description:
      - Domain the public key is related to.
    required: false
    default: null
  account:
    description:
      - Account the public key is related to.
    required: false
    default: null
  project:
    description:
      - Name of the project the public key to be registered in.
    required: false
    default: null
  state:
    description:
      - State of the public key.
    required: false
    default: 'present'
    choices: [ 'present', 'absent' ]
  public_key:
    description:
      - String of the public key.
    required: false
    default: null
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
# create a new private / public key pair:
- local_action: cs_sshkeypair name=linus@example.com
  register: key
- debug: msg='private key is {{ key.private_key }}'

# remove a public key by its name:
- local_action: cs_sshkeypair name=linus@example.com state=absent

# register your existing local public key:
- local_action: cs_sshkeypair name=linus@example.com public_key='{{ lookup('file', '~/.ssh/id_rsa.pub') }}'
'''

RETURN = '''
---
id:
  description: UUID of the SSH public key.
  returned: success
  type: string
  sample: a6f7a5fc-43f8-11e5-a151-feff819cdc9f
name:
  description: Name of the SSH public key.
  returned: success
  type: string
  sample: linus@example.com
fingerprint:
  description: Fingerprint of the SSH public key.
  returned: success
  type: string
  sample: "86:5e:a3:e8:bd:95:7b:07:7c:c2:5c:f7:ad:8b:09:28"
private_key:
  description: Private key of generated SSH keypair.
  returned: changed
  type: string
  sample: "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCkeFYjI+4k8bWfIRMzp4pCzhlopNydbbwRu824P5ilD4ATWMUG\nvEtuCQ2Mp5k5Bma30CdYHgh2/SbxC5RxXSUKTUJtTKpoJUy8PAhb1nn9dnfkC2oU\naRVi9NRUgypTIZxMpgooHOxvAzWxbZCyh1W+91Ld3FNaGxTLqTgeevY84wIDAQAB\nAoGAcwQwgLyUwsNB1vmjWwE0QEmvHS4FlhZyahhi4hGfZvbzAxSWHIK7YUT1c8KU\n9XsThEIN8aJ3GvcoL3OAqNKRnoNb14neejVHkYRadhxqc0GVN6AUIyCqoEMpvhFI\nQrinM572ORzv5ffRjCTbvZcYlW+sqFKNo5e8pYIB8TigpFECQQDu7bg9vkvg8xPs\nkP1K+EH0vsR6vUfy+m3euXjnbJtiP7RoTkZk0JQMOmexgy1qQhISWT0e451wd62v\nJ7M0trl5AkEAsDivJnMIlCCCypwPN4tdNUYpe9dtidR1zLmb3SA7wXk5xMUgLZI9\ncWPjBCMt0KKShdDhQ+hjXAyKQLF7iAPuOwJABjdHCMwvmy2XwhrPjCjDRoPEBtFv\n0sFzJE08+QBZVogDwIbwy+SlRWArnHGmN9J6N+H8dhZD3U4vxZPJ1MBAOQJBAJxO\nCv1dt1Q76gbwmYa49LnWO+F+2cgRTVODpr5iYt5fOmBQQRRqzFkRMkFvOqn+KVzM\nQ6LKM6dn8BEl295vLhUCQQCVDWzoSk3GjL3sOjfAUTyAj8VAXM69llaptxWWySPM\nE9pA+8rYmHfohYFx7FD5/KWCO+sfmxTNB48X0uwyE8tO\n-----END RSA PRIVATE KEY-----\n"
'''


try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

try:
    import sshpubkeys
    has_lib_sshpubkeys = True
except ImportError:
    has_lib_sshpubkeys = False

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
        # these keys will be compared case sensitive in self.has_changed()
        self.case_sensitive_keys = [
            'id',
        ]

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
                if self.case_sensitive_keys and key in self.case_sensitive_keys:
                    if str(value) != str(current_dict[key]):
                        return True
                # Test for diff in case insensitive way
                elif str(value).lower() != str(current_dict[key]).lower():
                    return True
            else:
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
        zones = self.cs.listZones()

        # use the first zone if no zone param given
        if not zone:
            self.zone = zones['zone'][0]
            return self._get_by_key(key, self.zone)

        if zones:
            for z in zones['zone']:
                if zone.lower() in [ z['name'].lower(), z['id'] ]:
                    self.zone = z
                    return self._get_by_key(key, self.zone)
        self.module.fail_json(msg="zone '%s' not found" % zone)


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

class AnsibleCloudStackSshKey(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackSshKey, self).__init__(module)
        self.returns = {
            'privatekey':   'private_key',
            'fingerprint':  'fingerprint',
        }
        self.ssh_key = None


    def register_ssh_key(self, public_key):
        ssh_key = self.get_ssh_key()
        args                = {}
        args['domainid']    = self.get_domain('id')
        args['account']     = self.get_account('name')
        args['projectid']   = self.get_project('id')
        args['name']        = self.module.params.get('name')

        res = None
        if not ssh_key:
            self.result['changed'] = True
            args['publickey'] = public_key
            if not self.module.check_mode:
                res = self.cs.registerSSHKeyPair(**args)

        else:
            fingerprint = self._get_ssh_fingerprint(public_key)
            if ssh_key['fingerprint'] != fingerprint:
                self.result['changed'] = True
                if not self.module.check_mode:
                    self.cs.deleteSSHKeyPair(**args)
                    args['publickey'] = public_key
                    res = self.cs.registerSSHKeyPair(**args)

        if res and 'keypair' in res:
            ssh_key = res['keypair']

        return ssh_key


    def create_ssh_key(self):
        ssh_key = self.get_ssh_key()
        if not ssh_key:
            self.result['changed'] = True
            args                = {}
            args['domainid']    = self.get_domain('id')
            args['account']     = self.get_account('name')
            args['projectid']   = self.get_project('id')
            args['name']        = self.module.params.get('name')
            if not self.module.check_mode:
                res = self.cs.createSSHKeyPair(**args)
                ssh_key = res['keypair']
        return ssh_key


    def remove_ssh_key(self):
        ssh_key = self.get_ssh_key()
        if ssh_key:
            self.result['changed'] = True
            args                = {}
            args['domainid']    = self.get_domain('id')
            args['account']     = self.get_account('name')
            args['projectid']   = self.get_project('id')
            args['name']        = self.module.params.get('name')
            if not self.module.check_mode:
                res = self.cs.deleteSSHKeyPair(**args)
        return ssh_key


    def get_ssh_key(self):
        if not self.ssh_key:
            args                = {}
            args['domainid']    = self.get_domain('id')
            args['account']     = self.get_account('name')
            args['projectid']   = self.get_project('id')
            args['name']        = self.module.params.get('name')

            ssh_keys = self.cs.listSSHKeyPairs(**args)
            if ssh_keys and 'sshkeypair' in ssh_keys:
                self.ssh_key = ssh_keys['sshkeypair'][0]
        return self.ssh_key



    def _get_ssh_fingerprint(self, public_key):
        key = sshpubkeys.SSHKey(public_key)
        return key.hash()


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        name = dict(required=True),
        public_key = dict(default=None),
        domain = dict(default=None),
        account = dict(default=None),
        project = dict(default=None),
        state = dict(choices=['present', 'absent'], default='present'),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=cs_required_together(),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    if not has_lib_sshpubkeys:
        module.fail_json(msg="python library sshpubkeys required: pip install sshpubkeys")

    try:
        acs_sshkey = AnsibleCloudStackSshKey(module)
        state = module.params.get('state')
        if state in ['absent']:
            ssh_key = acs_sshkey.remove_ssh_key()
        else:
            public_key = module.params.get('public_key')
            if public_key:
                ssh_key = acs_sshkey.register_ssh_key(public_key)
            else:
                ssh_key = acs_sshkey.create_ssh_key()

        result = acs_sshkey.get_result(ssh_key)

    except CloudStackException as e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
