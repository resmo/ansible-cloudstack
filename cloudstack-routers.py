#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (c) 2015, René Moser <mail@renemoser.net>
#
# This file is part of Ansible,
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

######################################################################

"""
Ansible CloudStack router inventory script.
=============================================

Generates Ansible inventory of routers from CloudStack. Configuration is read from
'cloudstack.ini'. If you need to pass the project, write a simple wrapper
script, e.g. project_cloudstack.sh:

  #!/bin/bash
  cloudstack-routers.py --project <your_project> $@


When run against a specific router, this script returns the following attributes
based on the data obtained from CloudStack API:

{
  "zone": "ZUERICH", 
  "default_ip": "1.2.3.4", 
  "nic": [
    {
      "ip": "10.101.66.1", 
      "mac": "02:00:46:28:00:02", 
      "netmask": "255.255.255.0"
    }, 
    {
      "ip": "10.100.9.134", 
      "mac": "02:00:00:38:06:4c", 
      "netmask": "255.255.255.0"
    }, 
    {
      "ip": "1.2.3.4", 
      "mac": "06:0c:fc:00:35:a1", 
      "netmask": "255.255.255.128"
    }
  ], 
  "ansible_ssh_host": "10.100.9.134", 
  "state": "Running", 
  "role": "VIRTUAL_ROUTER", 
  "service_offering": "System Offering for Software Router XLarge"
}


usage: cloudstack-routers.py [--list] [--host HOST] [--project PROJECT]
"""

import os
import sys
import argparse

try:
    import json
except:
    import simplejson as json


try:
    from cs import CloudStack, CloudStackException, read_config
except ImportError:
    print >> sys.stderr, "Error: CloudStack library must be installed: pip install cs."
    sys.exit(1)


class CloudStackInventory(object):
    def __init__(self):

        parser = argparse.ArgumentParser()
        parser.add_argument('--host')
        parser.add_argument('--list', action='store_true')
        parser.add_argument('--project')

        options = parser.parse_args()
        try:
            self.cs = CloudStack(**read_config())
        except CloudStackException, e:
            print >> sys.stderr, "Error: Could not connect to CloudStack API"

        project_id = -1
        if options.project:
            project_id = self.get_project_id(options.project)

        if options.host:
            data = self.get_host(options.host, project_id)
            print json.dumps(data, indent=2)

        elif options.list:
            data = self.get_list(project_id)
            print json.dumps(data, indent=2)
        else:
            print >> sys.stderr, "usage: --list | --host <hostname> [--project <project>]"
            sys.exit(1)


    def get_project_id(self, project):
        projects = self.cs.listProjects(listall=True)
        if projects:
            for p in projects['project']:
                if p['name'] == project or p['id'] == project:
                    return p['id']
        print >> sys.stderr, "Error: Project %s not found." % project
        sys.exit(1)

    def add_group(self, data, group_name, router_name):
        if group_name not in data:
            data[group_name] = {
                'hosts': []
            }
        data[group_name]['hosts'].append(router_name)
        return data

    def get_host(self, name, project_id):
        routers = []

        routers_projects = self.cs.listRouters(projectid=project_id, listall=True)
        if routers_projects and 'router' in routers_projects:
            routers = routers + routers_projects['router']

        routers_accounts = self.cs.listRouters(listall=True)
        if routers_accounts and 'router' in routers_accounts:
            routers = routers + routers_accounts['router']

        data = {}
        for router in routers:
            router_name = router['name']
            if name == router_name:
                data['zone'] = router['zonename']
                if 'linklocalip' in router:
                    data['ansible_ssh_host'] = router['linklocalip']
                data['state'] = router['state']
                data['redundant_state'] = router['redundantstate']
                if 'account' in router:
                    data['account'] = router['account']
                if 'project' in router:
                    data['project'] = router['project']
                data['service_offering'] = router['serviceofferingname']
                data['role'] = router['role']
                data['nic'] = []
                for nic in router['nic']:
                    data['nic'].append({
                        'ip': nic['ipaddress'],
                        'mac': nic['macaddress'],
                        'netmask': nic['netmask'],
                    })
                    if nic['isdefault']:
                        data['default_ip'] = nic['ipaddress']
                break;
        return data


    def get_list(self, project_id):
        data = {
            'all': {
                'hosts': [],
                },
            '_meta': {
                'hostvars': {},
                },
            }

        routers = []

        routers_projects = self.cs.listRouters(projectid=project_id, listall=True)
        if routers_projects and 'router' in routers_projects:
            routers = routers + routers_projects['router']

        routers_accounts = self.cs.listRouters(listall=True)
        if routers_accounts and 'router' in routers_accounts:
            routers = routers + routers_accounts['router']

        for router in routers:
            if router['state'] != 'Running':
                continue
            router_name = router['name']
            data['all']['hosts'].append(router_name)
            # Make a group per domain
            data = self.add_group(data, router['domain'], router_name)

            data['_meta']['hostvars'][router_name] = {}
            data['_meta']['hostvars'][router_name]['group'] = router['domain']
            data['_meta']['hostvars'][router_name]['domain'] = router['domain']
            if 'networkdomain' in router:
                data['_meta']['hostvars'][router_name]['networkdomain'] = router['networkdomain']

            data['_meta']['hostvars'][router_name]['zone'] = router['zonename']
            # Make a group per zone
            data = self.add_group(data, router['zonename'], router_name)

            if 'project' in router:
                data['_meta']['hostvars'][router_name]['project'] = router['project']

                # Make a group per project
                data = self.add_group(data, router['project'], router_name)

            if 'account' in router:
                data['_meta']['hostvars'][router_name]['account'] = router['account']

                # Make a group per account
                data = self.add_group(data, router['account'], router_name)

            data['_meta']['hostvars'][router_name]['ansible_ssh_host'] = router['linklocalip']
            data['_meta']['hostvars'][router_name]['state'] = router['state']
            if 'redundantstate' in router:
                data['_meta']['hostvars'][router_name]['redundant_state'] = router['redundantstate']

                if router['redundantstate'] in [ 'MASTER', 'BACKUP' ]:
                    data = self.add_group(data, 'redundant_routers', router_name)

                if router['redundantstate'] in [ 'MASTER' ]:
                    data = self.add_group(data, 'redundant_master_routers', router_name)

                if router['redundantstate'] in [ 'BACKUP' ]:
                    data = self.add_group(data, 'redundant_backup_routers', router_name)

                if router['redundantstate'] in [ 'UNKNOWN' ]:
                    data = self.add_group(data, 'non_redundant_routers', router_name)

            data['_meta']['hostvars'][router_name]['service_offering'] = router['serviceofferingname']
            data['_meta']['hostvars'][router_name]['nic'] = []
            for nic in router['nic']:
                data['_meta']['hostvars'][router_name]['nic'].append({
                    'ip': nic['ipaddress'],
                    'mac': nic['macaddress'],
                    'netmask': nic['netmask'],
                    })
                if nic['isdefault']:
                    data['_meta']['hostvars'][router_name]['default_ip'] = nic['ipaddress']
        return data


if __name__ == '__main__':
    CloudStackInventory()
