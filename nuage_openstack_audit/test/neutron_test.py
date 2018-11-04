# Copyright 2018 NOKIA
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import neutronclient.common.exceptions as neutron_exceptions

from nuage_openstack_audit.osclient.osclient import Neutron


class NeutronTest(Neutron):

    def create_router(self, name):
        return self.client.create_router(
            {'router': {
                'name': name}})['router']

    def delete_router(self, router):
        try:
            self.client.delete_router(router['id'])
        except neutron_exceptions.Conflict:
            print('router %s could not be deleted '
                  'as of conflict error.' % router['id'])

    def create_firewall_rule(self, protocol='tcp', action='allow',
                             enabled=True):
        return self.client.create_firewall_rule(
            {'firewall_rule': {
                'protocol': protocol,
                'action': action,
                'enabled': enabled}})['firewall_rule']

    def delete_firewall_rule(self, fw_rule):
        self.client.delete_firewall_rule(fw_rule['id'])

    def create_firewall_policy(self, name, rules):
        return self.client.create_firewall_policy(
            {'firewall_policy': {
                'name': name,
                'firewall_rules': rules}})['firewall_policy']

    def delete_firewall_policy(self, policy):
        self.client.delete_firewall_policy(policy['id'])

    def create_firewall(self, policy, router, admin_state_up=True):
        return self.client.create_firewall(
            {'firewall': {
                'router_ids': [router['id']],
                'firewall_policy_id': policy['id'],
                'admin_state_up': admin_state_up}})['firewall']

    def delete_firewall(self, fw):
        self.client.delete_firewall(fw['id'])
