#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015, Jefferson Girão <jefferson@girao.net>
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
module: cs_volume
short_description: Manages volumes on Apache CloudStack based clouds.
description:
    - Create, destroy, attach, detach volumes.
version_added: '2.0'
author:
    - "Jefferson Girão (@jeffersongirao)"
    - "René Moser (@resmo)"
options:
  name:
    description:
      - Name of the volume.
      - C(name) can only contain ASCII letters.
    required: true
  account:
    description:
      - Account the volume is related to.
    required: false
    default: null
  custom_id:
    description:
      - Custom id to the resource.
      - Allowed to Root Admins only.
    required: false
    default: null
  disk_offering:
    description:
      - Name of the disk offering to be used.
      - Required one of C(disk_offering), C(snapshot) if C(state=present).
    required: false
    default: null
  display_volume:
    description:
      - Whether to display the volume to the end user or not.
      - Allowed to Root Admins only.
    required: false
    default: true
  domain:
    description:
      - Name of the domain the volume to be deployed in.
    required: false
    default: null
  max_iops:
    description:
      - Max iops
    required: false
    default: null
  min_iops:
    description:
      - Min iops
    required: false
    default: null
  project:
    description:
      - Name of the project the volume to be deployed in.
    required: false
    default: null
  size:
    description:
      - Size of disk in GB
      - Required on C(state=present).
    required: false
    default: null
  snapshot:
    description:
      - The snapshot name for the disk volume.
      - Required one of C(disk_offering), C(snapshot) if C(state=present).
    required: false
    default: null
  force:
    description:
      - Force removal of volume even it is attached to a VM.
      - Considered on C(state=absnet) only.
    required: false
    default: false
  vm:
    description:
      - Name of the virtual machine to attach the volume to.
    required: false
    default: null
  zone:
    description:
      - Name of the zone in which the volume should be deployed.
      - If not set, default zone is used.
    required: false
    default: null
  state:
    description:
      - State of the volume.
    required: false
    default: 'present'
    choices: [ 'present', 'absent', 'attached', 'detached' ]
  poll_async:
    description:
      - Poll async jobs until job has finished.
    required: false
    default: true
extends_documentation_fragment: cloudstack
'''

EXAMPLES = '''
# Create volume within project, zone with specified storage options
- local_action:
    module: cs_volume
    name: web-vm-1-volume
    project: Integration
    zone: ch-zrh-ix-01
    disk_offering: PerfPlus Storage
    size: 20

# Create/attach volume to instance
- local_action:
    module: cs_volume
    name: web-vm-1-volume
    disk_offering: PerfPlus Storage
    size: 20
    vm: web-vm-1
    state: attached

# Detach volume
- local_action:
    module: cs_volume
    name: web-vm-1-volume
    state: detached

# Remove volume
- local_action:
    module: cs_volume
    name: web-vm-1-volume
    state: absent
'''

RETURN = '''
id:
  description: ID of the volume.
  returned: success
  type: string
  sample:
name:
  description: Name of the volume.
  returned: success
  type: string
  sample: web-volume-01
display_name:
  description: Display name of the volume.
  returned: success
  type: string
  sample: web-volume-01
group:
  description: Group the volume belongs to
  returned: success
  type: string
  sample: web
domain:
  description: Domain the volume belongs to
  returned: success
  type: string
  sample: example domain
project:
  description: Project the volume belongs to
  returned: success
  type: string
  sample: Production
zone:
  description: Name of zone the volume is in.
  returned: success
  type: string
  sample: ch-gva-2
created:
  description: Date of the volume was created.
  returned: success
  type: string
  sample: 2014-12-01T14:57:57+0100
attached:
  description: Date of the volume was attached.
  returned: success
  type: string
  sample: 2014-12-01T14:57:57+0100
type:
  description: Disk volume type.
  returned: success
  type: string
  sample: DATADISK
size:
  description: Size of disk volume.
  returned: success
  type: string
  sample: 20
vm:
  description: Name of the vm the volume is attached to (not returned when detached)
  returned: success
  type: string
  sample: web-01
state:
  description: State of the volume
  returned: success
  type: string
  sample: Attached
device_id:
  description: Id of the device on user vm the volume is attached to (not returned when detached)
  returned: success
  type: string
  sample: 1
'''

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

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

# import cloudstack common
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
                if isinstance(value, int):
                    current_dict[key] = int(current_dict[key])
                elif isinstance(value, str):
                    current_dict[key] = str(current_dict[key])

                # Only need to detect a singe change, not every item
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
                if vm in [ v['name'], v['displayname'], v['id'] ]:
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
                if zone in [ z['name'], z['id'] ]:
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


class AnsibleCloudStackVolume(AnsibleCloudStack):

    def __init__(self, module):
        super(AnsibleCloudStackVolume, self).__init__(module)
        self.returns = {
            'group':            'group',
            'attached':         'attached',
            'vmname':           'vm',
            'deviceid':         'device_id',
            'type':             'type',
            'size':             'size',
        }
        self.volume = None

    #TODO implement in cloudstack utils
    def get_disk_offering(self, key=None):
        disk_offering = self.module.params.get('disk_offering')
        if not disk_offering:
            return None

        args = {}
        args['domainid'] = self.get_domain(key='id')

        disk_offerings = self.cs.listDiskOfferings(**args)
        if disk_offerings:
            for d in disk_offerings['diskoffering']:
                if disk_offering in [d['displaytext'], d['name'], d['id']]:
                    return self._get_by_key(key, d)
        self.module.fail_json(msg="Disk offering '%s' not found" % disk_offering)


    def get_volume(self):
        if not self.volume:
            args = {}
            args['account'] = self.get_account(key='name')
            args['domainid'] = self.get_domain(key='id')
            args['projectid'] = self.get_project(key='id')
            args['type'] = 'DATADISK'

            volumes = self.cs.listVolumes(**args)
            if volumes:
                volume_name = self.module.params.get('name')
                for v in volumes['volume']:
                    if volume_name.lower() == v['name'].lower():
                        self.volume = v
                        break
        return self.volume


    def get_snapshot(self, key=None):
        snapshot = self.module.params.get('snapshot')
        if not snapshot:
            return None

        args = {}
        args['name'] = snapshot
        args['account'] = self.get_account('name')
        args['domainid'] = self.get_domain('id')
        args['projectid'] = self.get_project('id')

        snapshots = self.cs.listSnapshots(**args)
        if snapshots:
            return self._get_by_key(key, snapshots['snapshot'][0])
        self.module.fail_json(msg="Snapshot with name %s not found" % snapshot)


    def present_volume(self):
        disk_offering_id = self.get_disk_offering(key='id')
        snapshot_id = self.get_snapshot(key='id')

        if not disk_offering_id and not snapshot_id:
            self.module.fail_json(msg="Required one of: disk_offering,snapshot")

        volume = self.get_volume()

        if not volume:
            self.result['changed'] = True

            args = {}
            args['name'] = self.module.params.get('name')
            args['account'] = self.get_account(key='name')
            args['domainid'] = self.get_domain(key='id')
            args['diskofferingid'] = disk_offering_id
            args['displayvolume'] = self.module.params.get('display_volume')
            args['maxiops'] = self.module.params.get('max_iops')
            args['miniops'] = self.module.params.get('min_iops')
            args['projectid'] = self.get_project(key='id')
            args['size'] = self.module.params.get('size')
            args['snapshotid'] = snapshot_id
            args['zoneid'] = self.get_zone(key='id')

            if not self.module.check_mode:
                res = self.cs.createVolume(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    volume = self.poll_job(res, 'volume')
        return volume


    def attached_volume(self):
        volume = self.present_volume()

        if volume.get('virtualmachineid') != self.get_vm(key='id'):
            self.result['changed'] = True

            if not self.module.check_mode:
                volume = self.detached_volume()

        if 'attached' not in volume:
            self.result['changed'] = True

            args = {}
            args['id'] = volume['id']
            args['virtualmachineid'] = self.get_vm(key='id')
            args['deviceid'] = self.module.params.get('device_id')

            if not self.module.check_mode:
                res = self.cs.attachVolume(**args)
                if 'errortext' in res:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    volume = self.poll_job(res, 'volume')
        return volume


    def detached_volume(self):
        volume = self.get_volume()

        if volume:
            if 'attached' not in volume:
                return volume

            self.result['changed'] = True

            if not self.module.check_mode:
                res = self.cs.detachVolume(id=volume['id'])
                if 'errortext' in volume:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    volume = self.poll_job(res, 'volume')
        return volume


    def absent_volume(self):
        volume = self.get_volume()

        if volume:
            if 'attached' in volume:
                if self.module.param.get('force'):
                    self.detached_volume()
                else:
                    self.module.fail_json(msg="Volume '%s' is attached, use force=true for detaching and removing the volume." % volume.get('name'))

            self.result['changed'] = True
            if not self.module.check_mode:
                volume = self.detached_volume()

                res = self.cs.deleteVolume(id=volume['id'])
                if 'errortext' in volume:
                    self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    res = self.poll_job(res, 'volume')

        return volume


def main():
    argument_spec = cs_argument_spec()
    argument_spec.update(dict(
        name = dict(required=True),
        disk_offering = dict(default=None),
        display_volume = dict(choices=BOOLEANS, default=True),
        max_iops = dict(type='int', default=None),
        min_iops = dict(type='int', default=None),
        size = dict(type='int', default=None),
        snapshot = dict(default=None),
        vm = dict(default=None),
        device_id = dict(type='int', default=None),
        custom_id = dict(default=None),
        force = dict(choices=BOOLEANS, default=False),
        state = dict(choices=['present', 'absent', 'attached', 'detached'], default='present'),
        zone = dict(default=None),
        domain = dict(default=None),
        account = dict(default=None),
        project = dict(default=None),
        poll_async = dict(choices=BOOLEANS, default=True),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=cs_required_together(),
        mutually_exclusive = (
            ['snapshot', 'disk_offering'],
        ),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_vol = AnsibleCloudStackVolume(module)

        state = module.params.get('state')

        if state in ['absent']:
            volume = acs_vol.absent_volume()
        elif state in ['attached']:
            volume = acs_vol.attached_volume()
        elif state in ['detached']:
            volume = acs_vol.detached_volume()
        else:
            volume = acs_vol.present_volume()

        result = acs_vol.get_result(volume)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
