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
module: cs_instance
short_description: Manages instances and virtual machines on Apache CloudStack based clouds.
description:
    - Deploy, start, restart, stop and destroy instances on Apache CloudStack, Citrix CloudPlatform and Exoscale.
version_added: '2.0'
author: René Moser
options:
  name:
    description:
      - Host name of the instance. C(name) can only contain ASCII letters.
    required: true
  display_name:
    description:
      - Custom display name of the instances.
    required: false
    default: null
  group:
    description:
      - Group in where the new instance should be in.
    required: false
    default: null
  state:
    description:
      - State of the instance.
    required: false
    default: 'present'
    choices: [ 'deployed', 'started', 'stopped', 'restarted', 'destroyed', 'expunged', 'present', 'absent' ]
  service_offering:
    description:
      - Name or id of the service offering of the new instance. If not set, first found service offering is used.
    required: false
    default: null
  template:
    description:
      - Name or id of the template to be used for creating the new instance. Required when using C(state=present). Mutually exclusive with C(ISO) option.
    required: false
    default: null
  iso:
    description:
      - Name or id of the ISO to be used for creating the new instance. Required when using C(state=present). Mutually exclusive with C(template) option.
    required: false
    default: null
  hypervisor:
    description:
      - Name the hypervisor to be used for creating the new instance. Relevant when using C(state=present) and option C(ISO) is used. If not set, first found hypervisor will be used.
    required: false
    default: null
    choices: [ 'KVM', 'VMware', 'BareMetal', 'XenServer', 'LXC', 'HyperV', 'UCS', 'OVM' ]
  keyboard:
    description:
      - Keyboard device type for the instance.
    required: false
    default: null
    choices: [ 'de', 'de-ch', 'es', 'fi', 'fr', 'fr-be', 'fr-ch', 'is', 'it', 'jp', 'nl-be', 'no', 'pt', 'uk', 'us' ]
  networks:
    description:
      - List of networks to use for the new instance.
    required: false
    default: []
    aliases: [ 'network' ]
  ip_address:
    description:
      - IPv4 address for default instance's network during creation
    required: false
    default: null
  ip6_address:
    description:
      - IPv6 address for default instance's network.
    required: false
    default: null
  disk_offering:
    description:
      - Name of the disk offering to be used.
    required: false
    default: null
  disk_size:
    description:
      - Disk size in GByte required if deploying instance from ISO.
    required: false
    default: null
  security_groups:
    description:
      - List of security groups the instance to be applied to.
    required: false
    default: []
    aliases: [ 'security_group' ]
  project:
    description:
      - Name of the project the instance to be deployed in.
    required: false
    default: null
  zone:
    description:
      - Name of the zone in which the instance shoud be deployed. If not set, default zone is used.
    required: false
    default: null
  ssh_key:
    description:
      - Name of the SSH key to be deployed on the new instance.
    required: false
    default: null
  affinity_groups:
    description:
      - Affinity groups names to be applied to the new instance.
    required: false
    default: []
    aliases: [ 'affinity_group' ]
  user_data:
    description:
      - Optional data (ASCII) that can be sent to the instance upon a successful deployment.
      - The data will be automatically base64 encoded.
      - Consider switching to HTTP_POST by using C(CLOUDSTACK_METHOD=post) to increase the HTTP_GET size limit of 2KB to 32 KB.
    required: false
    default: null
  force:
    description:
      - Force stop/start the instance if required to apply changes, otherwise a running instance will not be changed.
    required: false
    default: true
  tags:
    description:
      - List of tags. Tags are a list of dictionaries having keys C(key) and C(value).
      - If you want to delete all tags, set a empty list e.g. C(tags: []).
    required: false
    default: null
  poll_async:
    description:
      - Poll async jobs until job has finished.
    required: false
    default: true
'''

EXAMPLES = '''
---
# Create a instance on CloudStack from an ISO
# NOTE: Names of offerings and ISOs depending on the CloudStack configuration.
- local_action:
    module: cs_instance
    name: web-vm-1
    iso: Linux Debian 7 64-bit
    hypervisor: VMware
    project: Integration
    zone: ch-zrh-ix-01
    service_offering: 1cpu_1gb
    disk_offering: PerfPlus Storage
    disk_size: 20
    networks:
      - Server Integration
      - Sync Integration
      - Storage Integration


# For changing a running instance, use the 'force' parameter
- local_action:
    module: cs_instance
    name: web-vm-1
    display_name: web-vm-01.example.com 
    iso: Linux Debian 7 64-bit
    service_offering: 2cpu_2gb
    force: yes


# Create or update a instance on Exoscale's public cloud
- local_action:
    module: cs_instance
    name: web-vm-1
    template: Linux Debian 7 64-bit
    service_offering: Tiny
    ssh_key: john@example.com
  register: vm

- debug: msg='default ip {{ vm.default_ip }} and is in state {{ vm.state }}'


# Ensure a instance has stopped
- local_action: cs_instance name=web-vm-1 state=stopped


# Ensure a instance is running
- local_action: cs_instance name=web-vm-1 state=started


# Remove a instance
- local_action: cs_instance name=web-vm-1 state=absent
'''

RETURN = '''
---
id:
  description: ID of the instance.
  returned: success
  type: string
  sample: 04589590-ac63-4ffc-93f5-b698b8ac38b6
name:
  description: Name of the instance.
  returned: success
  type: string
  sample: web-01
display_name:
  description: Display name of the instance.
  returned: success
  type: string
  sample: web-01
group:
  description: Group name of the instance is related.
  returned: success
  type: string
  sample: web
created:
  description: Date of the instance was created.
  returned: success
  type: string
  sample: 2014-12-01T14:57:57+0100
password_enabled:
  description: True if password setting is enabled.
  returned: success
  type: boolean
  sample: true
password:
  description: The password of the instance if exists.
  returned: success
  type: string
  sample: Ge2oe7Do
ssh_key:
  description: Name of ssh key deployed to instance.
  returned: success
  type: string
  sample: key@work
project:
  description: Name of project the instance is related to.
  returned: success
  type: string
  sample: Production
default_ip:
  description: Default IP address of the instance.
  returned: success
  type: string
  sample: 10.23.37.42
public_ip:
  description: Public IP address with instance via static nat rule.
  returned: success
  type: string
  sample: 1.2.3.4
iso:
  description: Name of ISO the instance was deployed with.
  returned: success
  type: string
  sample: Debian-8-64bit
template:
  description: Name of template the instance was deployed with.
  returned: success
  type: string
  sample: Debian-8-64bit
service_offering:
  description: Name of the service offering the instance has.
  returned: success
  type: string
  sample: 2cpu_2gb
zone:
  description: Name of zone the instance is in.
  returned: success
  type: string
  sample: ch-gva-2
state:
  description: State of the instance.
  returned: success
  type: string
  sample: Running
tags:
  description: List of resource tags associated with the instance.
  returned: success
  type: dict
  sample: '{ bar: foo, for: bar }'
'''

import base64

try:
    from cs import CloudStack, CloudStackException, read_config
    has_lib_cs = True
except ImportError:
    has_lib_cs = False

class AnsibleCloudStack:

    def __init__(self, module):
        if not has_lib_cs:
            module.fail_json(msg="python library cs required: pip install cs")

        self.result = {
            'changed': False,
        }

        self.module = module
        self._connect()

        self.project = None
        self.ip_address = None
        self.zone = None
        self.vm = None
        self.os_type = None
        self.hypervisor = None
        self.capabilities = None


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


    def _has_changed(self, want_dict, current_dict, only_keys=None):
        for key, value in want_dict.iteritems():

            # Optionally limit by a list of keys
            if only_keys and key not in only_keys:
                continue;

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


    def _get_by_key(self, key=None, my_dict={}):
        if key:
            if key in my_dict:
                return my_dict[key]
            self.module.fail_json(msg="Something went wrong: %s not found" % key)
        return my_dict


    # TODO: for backward compatibility only, remove if not used anymore
    def get_project_id(self):
        return self.get_project(key='id')


    def get_project(self, key=None):
        if self.project:
            return self._get_by_key(key, self.project)

        project = self.module.params.get('project')
        if not project:
            return None

        projects = self.cs.listProjects(listall=True)
        if projects:
            for p in projects['project']:
                if project in [ p['name'], p['displaytext'], p['id'] ]:
                    self.project = p
                    return self._get_by_key(key, self.project)
        self.module.fail_json(msg="project '%s' not found" % project)


    # TODO: for backward compatibility only, remove if not used anymore
    def get_ip_address_id(self):
        return self.get_ip_address(key='id')


    def get_ip_address(self, key=None):
        if self.ip_address:
            return self._get_by_key(key, self.ip_address)

        ip_address = self.module.params.get('ip_address')
        if not ip_address:
            self.module.fail_json(msg="IP address param 'ip_address' is required")

        args = {}
        args['ipaddress'] = ip_address
        args['projectid'] = self.get_project(key='id')
        ip_addresses = self.cs.listPublicIpAddresses(**args)

        if not ip_addresses:
            self.module.fail_json(msg="IP address '%s' not found" % args['ipaddress'])

        self.ip_address = ip_addresses['publicipaddress'][0]
        return self._get_by_key(key, self.ip_address)


    # TODO: for backward compatibility only, remove if not used anymore
    def get_vm_id(self):
        return self.get_vm(key='id')


    def get_vm(self, key=None):
        if self.vm:
            return self._get_by_key(key, self.vm)

        vm = self.module.params.get('vm')
        if not vm:
            self.module.fail_json(msg="Virtual machine param 'vm' is required")

        args = {}
        args['projectid'] = self.get_project(key='id')
        args['zoneid'] = self.get_zone(key='id')
        vms = self.cs.listVirtualMachines(**args)
        if vms:
            for v in vms['virtualmachine']:
                if vm in [ v['name'], v['displayname'], v['id'] ]:
                    self.vm = v
                    return self._get_by_key(key, self.vm)
        self.module.fail_json(msg="Virtual machine '%s' not found" % vm)


    # TODO: for backward compatibility only, remove if not used anymore
    def get_zone_id(self):
        return self.get_zone(key='id')


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


    # TODO: for backward compatibility only, remove if not used anymore
    def get_os_type_id(self):
        return self.get_os_type(key='id')


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


    def get_tags(self, resource=None):
        existing_tags = self.cs.listTags(resourceid=resource['id'])
        if existing_tags:
            return existing_tags['tag']
        return []


    def _delete_tags(self, resource, resource_type, tags):
        existing_tags = resource['tags']
        tags_to_delete = []
        for existing_tag in existing_tags:
            if existing_tag['key'] in tags:
                if existing_tag['value'] != tags[key]:
                    tags_to_delete.append(existing_tag)
            else:
                tags_to_delete.append(existing_tag)
        if tags_to_delete:
            self.result['changed'] = True
            if not self.module.check_mode:
                args = {}
                args['resourceids']  = resource['id']
                args['resourcetype'] = resource_type
                args['tags']         = tags_to_delete
                self.cs.deleteTags(**args)


    def _create_tags(self, resource, resource_type, tags):
        tags_to_create = []
        for i, tag_entry in enumerate(tags):
            tag = {
                'key':   tag_entry['key'],
                'value': tag_entry['value'],
            }
            tags_to_create.append(tag)
        if tags_to_create:
            self.result['changed'] = True
            if not self.module.check_mode:
                args = {}
                args['resourceids']  = resource['id']
                args['resourcetype'] = resource_type
                args['tags']         = tags_to_create
                self.cs.createTags(**args)


    def ensure_tags(self, resource, resource_type=None):
        if not resource_type or not resource:
            self.module.fail_json(msg="Error: Missing resource or resource_type for tags.")

        tags = self.module.params.get('tags')
        if tags is not None:
            self._delete_tags(resource, resource_type, tags)
            self._create_tags(resource, resource_type, tags)
            resource['tags'] = self.get_tags(resource)
        return resource


    def get_capabilities(self, key=None):
        if self.capabilities:
            return self._get_by_key(key, self.capabilities)
        capabilities = self.cs.listCapabilities()
        self.capabilities = capabilities['capability']
        return self._get_by_key(key, self.capabilities)


    def _poll_job(self, job=None, key=None):
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


class AnsibleCloudStackInstance(AnsibleCloudStack):

    def __init__(self, module):
        AnsibleCloudStack.__init__(self, module)
        self.instance = None


    def get_service_offering_id(self):
        service_offering = self.module.params.get('service_offering')

        service_offerings = self.cs.listServiceOfferings()
        if service_offerings:
            if not service_offering:
                return service_offerings['serviceoffering'][0]['id']

            for s in service_offerings['serviceoffering']:
                if service_offering in [ s['name'], s['id'] ]:
                    return s['id']
        self.module.fail_json(msg="Service offering '%s' not found" % service_offering)


    def get_template_or_iso_id(self):
        template = self.module.params.get('template')
        iso = self.module.params.get('iso')

        if not template and not iso:
            self.module.fail_json(msg="Template or ISO is required.")

        if template and iso:
            self.module.fail_json(msg="Template are ISO are mutually exclusive.")

        if template:
            templates = self.cs.listTemplates(templatefilter='executable')
            if templates:
                for t in templates['template']:
                    if template in [ t['displaytext'], t['name'], t['id'] ]:
                        return t['id']
            self.module.fail_json(msg="Template '%s' not found" % template)

        elif iso:
            isos = self.cs.listIsos()
            if isos:
                for i in isos['iso']:
                    if iso in [ i['displaytext'], i['name'], i['id'] ]:
                        return i['id']
            self.module.fail_json(msg="ISO '%s' not found" % iso)


    def get_disk_offering_id(self):
        disk_offering = self.module.params.get('disk_offering')

        if not disk_offering:
            return None

        disk_offerings = self.cs.listDiskOfferings()
        if disk_offerings:
            for d in disk_offerings['diskoffering']:
                if disk_offering in [ d['displaytext'], d['name'], d['id'] ]:
                    return d['id']
        self.module.fail_json(msg="Disk offering '%s' not found" % disk_offering)


    def get_instance(self):
        instance = self.instance
        if not instance:
            instance_name = self.module.params.get('name')

            args = {}
            args['projectid'] = self.get_project_id()
            args['zoneid'] = self.get_zone_id()
            instances = self.cs.listVirtualMachines(**args)
            if instances:
                for v in instances['virtualmachine']:
                    if instance_name in [ v['name'], v['displayname'], v['id'] ]:
                        self.instance = v
                        break
        return self.instance


    def get_network_ids(self):
        network_names = self.module.params.get('networks')
        if not network_names:
            return None

        args = {}
        args['zoneid'] = self.get_zone_id()
        args['projectid'] = self.get_project_id()
        networks = self.cs.listNetworks(**args)
        if not networks:
            self.module.fail_json(msg="No networks available")

        network_ids = []
        network_displaytexts = []
        for network_name in network_names:
            for n in networks['network']:
                if network_name in [ n['displaytext'], n['name'], n['id'] ]:
                    network_ids.append(n['id'])
                    network_displaytexts.append(n['name'])
                    break

        if len(network_ids) != len(network_names):
            self.module.fail_json(msg="Could not find all networks, networks list found: %s" % network_displaytexts)

        return ','.join(network_ids)


    def ensure_instance(self):
        instance = self.get_instance()
        if not instance:
            instance = self.deploy_instance()
        else:
            instance = self.update_instance(instance)
        
        instance = self.ensure_tags(resource=instance, resource_type='UserVm')

        return instance


    def get_user_data(self):
        user_data = self.module.params.get('user_data')
        if user_data:
            user_data = base64.b64encode(user_data)
        return user_data


    def get_display_name(self):
        display_name = self.module.params.get('display_name')
        if not display_name:
            display_name = self.module.params.get('name')
        return display_name


    def deploy_instance(self):
        self.result['changed'] = True

        args                        = {}
        args['templateid']          = self.get_template_or_iso_id()
        args['zoneid']              = self.get_zone_id()
        args['serviceofferingid']   = self.get_service_offering_id()
        args['projectid']           = self.get_project_id()
        args['diskofferingid']      = self.get_disk_offering_id()
        args['networkids']          = self.get_network_ids()
        args['hypervisor']          = self.get_hypervisor()
        args['userdata']            = self.get_user_data()
        args['keyboard']            = self.module.params.get('keyboard')
        args['ipaddress']           = self.module.params.get('ip_address')
        args['ip6address']          = self.module.params.get('ip6_address')
        args['name']                = self.module.params.get('name')
        args['group']               = self.module.params.get('group')
        args['keypair']             = self.module.params.get('ssh_key')
        args['size']                = self.module.params.get('disk_size')
        args['securitygroupnames']  = ','.join(self.module.params.get('security_groups'))
        args['affinitygroupnames']  = ','.join(self.module.params.get('affinity_groups'))

        if not self.module.check_mode:
            instance = self.cs.deployVirtualMachine(**args)

            if 'errortext' in instance:
                self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

            poll_async = self.module.params.get('poll_async')
            if poll_async:
                instance = self._poll_job(instance, 'virtualmachine')
        return instance


    def update_instance(self, instance):
        args_service_offering                       = {}
        args_service_offering['id']                 = instance['id']
        args_service_offering['serviceofferingid']  = self.get_service_offering_id()

        args_instance_update                        = {}
        args_instance_update['id']                  = instance['id']
        args_instance_update['group']               = self.module.params.get('group')
        args_instance_update['displayname']         = self.get_display_name()
        args_instance_update['userdata']            = self.get_user_data()
        args_instance_update['ostypeid']            = self.get_os_type_id()

        args_ssh_key                                = {}
        args_ssh_key['id']                          = instance['id']
        args_ssh_key['keypair']                     = self.module.params.get('ssh_key')
        args_ssh_key['projectid']                   = self.get_project_id()
        
        if self._has_changed(args_service_offering, instance) or \
           self._has_changed(args_instance_update, instance) or \
           self._has_changed(args_ssh_key, instance):
 
            force = self.module.params.get('force')
            instance_state = instance['state'].lower()
            
            if instance_state == 'stopped' or force:
                self.result['changed'] = True
                if not self.module.check_mode:

                    # Ensure VM has stopped
                    instance = self.stop_instance()
                    instance = self._poll_job(instance, 'virtualmachine')
                    self.instance = instance

                    # Change service offering
                    if self._has_changed(args_service_offering, instance):
                        res = self.cs.changeServiceForVirtualMachine(**args_service_offering)
                        if 'errortext' in res:
                            self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                        instance = res['virtualmachine']
                        self.instance = instance

                    # Update VM
                    if self._has_changed(args_instance_update, instance):
                        res = self.cs.updateVirtualMachine(**args_instance_update)
                        if 'errortext' in res:
                            self.module.fail_json(msg="Failed: '%s'" % res['errortext'])
                        instance = res['virtualmachine']
                        self.instance = instance

                    # Reset SSH key
                    if self._has_changed(args_ssh_key, instance):
                        instance = self.cs.resetSSHKeyForVirtualMachine(**args_ssh_key)
                        if 'errortext' in instance:
                            self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                        instance = self._poll_job(instance, 'virtualmachine')
                        self.instance = instance

                    # Start VM again if it was running before
                    if instance_state == 'running':
                        instance = self.start_instance()

        return instance


    def remove_instance(self):
        instance = self.get_instance()
        if instance:
            if instance['state'].lower() not in ['expunging', 'destroying', 'destroyed']:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.destroyVirtualMachine(id=instance['id'])

                    if 'errortext' in res:
                        self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

                    poll_async = self.module.params.get('poll_async')
                    if poll_async:
                        instance = self._poll_job(res, 'virtualmachine')
        return instance


    def expunge_instance(self):
        instance = self.get_instance()
        if instance:
            res = {}
            if instance['state'].lower() in [ 'destroying', 'destroyed' ]:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.expungeVirtualMachine(id=instance['id'])

            elif instance['state'].lower() not in [ 'expunging' ]:
                self.result['changed'] = True
                if not self.module.check_mode:
                    res = self.cs.destroyVirtualMachine(id=instance['id'], expunge=True)

            if res and 'errortext' in res:
                self.module.fail_json(msg="Failed: '%s'" % res['errortext'])

            poll_async = self.module.params.get('poll_async')
            if poll_async:
                instance = self._poll_job(res, 'virtualmachine')
        return instance


    def stop_instance(self):
        instance = self.get_instance()
        if not instance:
            self.module.fail_json(msg="Instance named '%s' not found" % self.module.params.get('name'))

        if instance['state'].lower() in ['stopping', 'stopped']:
            return instance

        if instance['state'].lower() in ['starting', 'running']:
            self.result['changed'] = True
            if not self.module.check_mode:
                instance = self.cs.stopVirtualMachine(id=instance['id'])

                if 'errortext' in instance:
                    self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    instance = self._poll_job(instance, 'virtualmachine')
        return instance


    def start_instance(self):
        instance = self.get_instance()
        if not instance:
            self.module.fail_json(msg="Instance named '%s' not found" % module.params.get('name'))

        if instance['state'].lower() in ['starting', 'running']:
            return instance

        if instance['state'].lower() in ['stopped', 'stopping']:
            self.result['changed'] = True
            if not self.module.check_mode:
                instance = self.cs.startVirtualMachine(id=instance['id'])

                if 'errortext' in instance:
                    self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    instance = self._poll_job(instance, 'virtualmachine')
        return instance


    def restart_instance(self):
        instance = self.get_instance()
        if not instance:
            module.fail_json(msg="Instance named '%s' not found" % self.module.params.get('name'))

        if instance['state'].lower() in [ 'running', 'starting' ]:
            self.result['changed'] = True
            if not self.module.check_mode:
                instance = self.cs.rebootVirtualMachine(id=instance['id'])

                if 'errortext' in instance:
                    self.module.fail_json(msg="Failed: '%s'" % instance['errortext'])

                poll_async = self.module.params.get('poll_async')
                if poll_async:
                    instance = self._poll_job(instance, 'virtualmachine')

        elif instance['state'].lower() in [ 'stopping', 'stopped' ]:
            instance = self.start_instance()
        return instance


    def get_result(self, instance):
        if instance:
            if 'id' in instance:
                self.result['id'] = instance['id']
            if 'name' in instance:
                self.result['name'] = instance['name']
            if 'displayname' in instance:
                self.result['display_name'] = instance['displayname']
            if 'group' in instance:
                self.result['group'] = instance['group']
            if 'project' in instance:
                self.result['project'] = instance['project']
            if 'publicip' in instance:
                self.result['public_ip'] = instance['public_ip']
            if 'passwordenabled' in instance:
                self.result['password_enabled'] = instance['passwordenabled']
            if 'password' in instance:
                self.result['password'] = instance['password']
            if 'serviceofferingname' in instance:
                self.result['service_offering'] = instance['serviceofferingname']
            if 'zonename' in instance:
                self.result['zone'] = instance['zonename']
            if 'templatename' in instance:
                self.result['template'] = instance['templatename']
            if 'isoname' in instance:
                self.result['iso'] = instance['isoname']
            if 'keypair' in instance:
                self.result['ssh_key'] = instance['keypair']
            if 'created' in instance:
                self.result['created'] = instance['created']
            if 'state' in instance:
                self.result['state'] = instance['state']
            if 'tags' in instance:
                tags = {}
                for tag in instance['tags']:
                    key = tag['key']
                    value = tag['value']
                    tags[key] = value
                self.result['tags'] = tags
            if 'nic' in instance:
                for nic in instance['nic']:
                    if nic['isdefault']:
                        self.result['default_ip'] = nic['ipaddress']
        return self.result

def main():
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True),
            display_name = dict(default=None),
            group = dict(default=None),
            state = dict(choices=['present', 'deployed', 'started', 'stopped', 'restarted', 'absent', 'destroyed', 'expunged'], default='present'),
            service_offering = dict(default=None),
            template = dict(default=None),
            iso = dict(default=None),
            networks = dict(type='list', aliases=[ 'network' ], default=None),
            ip_address = dict(defaul=None),
            ip6_address = dict(defaul=None),
            disk_offering = dict(default=None),
            disk_size = dict(type='int', default=None),
            keyboard = dict(choices=['de', 'de-ch', 'es', 'fi', 'fr', 'fr-be', 'fr-ch', 'is', 'it', 'jp', 'nl-be', 'no', 'pt', 'uk', 'us'], default=None),
            hypervisor = dict(default=None),
            security_groups = dict(type='list', aliases=[ 'security_group' ], default=[]),
            affinity_groups = dict(type='list', aliases=[ 'affinity_group' ], default=[]),
            project = dict(default=None),
            user_data = dict(default=None),
            zone = dict(default=None),
            ssh_key = dict(default=None),
            force = dict(choices=BOOLEANS, default=False),
            tags = dict(type='list', aliases=[ 'tag' ], default=None),
            poll_async = dict(choices=BOOLEANS, default=True),
            api_key = dict(default=None),
            api_secret = dict(default=None),
            api_url = dict(default=None),
            api_http_method = dict(default='get'),
        ),
        supports_check_mode=True
    )

    if not has_lib_cs:
        module.fail_json(msg="python library cs required: pip install cs")

    try:
        acs_instance = AnsibleCloudStackInstance(module)

        state = module.params.get('state')

        if state in ['absent', 'destroyed']:
            instance = acs_instance.remove_instance()

        elif state in ['expunged']:
            instance = acs_instance.expunge_instance()

        elif state in ['present', 'deployed']:
            instance = acs_instance.ensure_instance()

        elif state in ['stopped']:
            instance = acs_instance.stop_instance()

        elif state in ['started']:
            instance = acs_instance.start_instance()

        elif state in ['restarted']:
            instance = acs_instance.restart_instance()

        if instance and 'state' in instance and instance['state'].lower() == 'error':
            module.fail_json(msg="Instance named '%s' in error state." % module.params.get('name'))

        result = acs_instance.get_result(instance)

    except CloudStackException, e:
        module.fail_json(msg='CloudStackException: %s' % str(e))

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
