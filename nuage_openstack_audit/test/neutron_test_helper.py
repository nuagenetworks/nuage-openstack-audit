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


class NeutronTestHelper(Neutron):

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

    def create_network(self, name, admin_state_up=True):
        return self.client.create_network(
            {"network": {
                "name": name,
                "admin_state_up": admin_state_up}
             })['network']

    def delete_network(self, network_id):
        self.client.delete_network(network_id)

    def create_subnet(self, network_id, ip_version, cidr):
        return self.client.create_subnet(
            {"subnet": {"network_id": network_id, "ip_version": ip_version,
                        "cidr": cidr}}
        )['subnet']

    def delete_subnet(self, subnet_id):
        self.client.delete_subnet(subnet_id)

    def create_port(self, network, **kwargs):
        """Wrapper utility that returns a test port."""
        body = kwargs or {}
        body['network_id'] = network['id']
        body = {'port': body}
        port = self.client.create_port(body)['port']

        return port

    def delete_port(self, port_id):
        self.client.delete_port(port_id)

    def create_router_interface(self, router_id, subnet_id):
        body = {
            'subnet_id': subnet_id
        }
        return self.client.add_interface_router(router_id, body)

    def delete_router_interface(self, router_id, subnet_id):
        body = {
            'subnet_id': subnet_id
        }
        return self.client.remove_interface_router(router_id, body)

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

    def create_security_group(self, name):
        return self.client.create_security_group(
            {"security_group": {
                "name": name}}
        )['security_group']

    def delete_security_group(self, sg_id):
        self.client.delete_security_group(sg_id)

    def create_security_group_rule(self, protocol, security_group_id,
                                   ether_type='IPv4', direction='ingress',
                                   remote_ip_prefix='0.0.0.0/0'):
        return self.client.create_security_group_rule(
            {"security_group_rule": {
                "ethertype": ether_type, "direction": direction,
                "remote_ip_prefix": remote_ip_prefix,
                "protocol": protocol,
                "security_group_id": security_group_id}}
        )['security_group_rule']

    def delete_security_group_rule(self, rule_id):
        self.client.delete_security_group_rule(rule_id)
