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

import netaddr
from nuage_openstack_audit.utils import constants

from nuage_openstack_audit.utils.matcher import Matcher
from nuage_openstack_audit.vsdclient.common import constants as vsd_constants


OS_ACTION_TO_VSD_ACTION = {
    'allow': 'FORWARD',
    'deny': 'DROP'
}

OS_ACTION_TO_VSD_STATEFUL = {
    'allow': True,
    'deny': False
}

OS_IPVERSION_TO_VSD_ETHERTYPE = {
    4: vsd_constants.VSP_IPV4_ETHERTYPE,
    6: vsd_constants.VSP_IPV6_ETHERTYPE
}


OS_FWAAS_RULES_TO_VSD = None


class FirewallPolicyMatcher(Matcher):

    def __init__(self, os_fwaas_rules_to_vsd_f):
        global OS_FWAAS_RULES_TO_VSD
        OS_FWAAS_RULES_TO_VSD = os_fwaas_rules_to_vsd_f

    def entity_name(self):
        return 'Firewall policy'

    def get_mapper(self):
        return {
            'name': [('name', lambda x: x)],
            'description': [('description', lambda x: x)],
            'firewall_rules': [
                ('rule_ids', OS_FWAAS_RULES_TO_VSD)
            ]
        }


class FirewallRuleMatcher(Matcher):

    def entity_name(self):
        return 'Firewall rule'

    def map_to_vsd_object(self, fw_rule):
        return {
            'address_override': self._map_address_override(fw_rule),
            'ipv6_address_override': self._map_ipv6_address_override(fw_rule),
            'description': fw_rule['name'],
            'network_id': self._map_network_id(fw_rule),
            'network_type': self._map_network_type(fw_rule),
            'source_port': self._map_source_port(fw_rule),
            'protocol': constants.IP_PROTOCOL_MAP.get(fw_rule['protocol'],
                                                      'ANY'),
            'destination_port': self._map_destination_port(fw_rule),
            'action': OS_ACTION_TO_VSD_ACTION[fw_rule['action']],
            'stateful': OS_ACTION_TO_VSD_STATEFUL[fw_rule['action']],
            'ether_type': OS_IPVERSION_TO_VSD_ETHERTYPE[fw_rule['ip_version']]
        }

    @staticmethod
    def _map_address_override(fw_rule):
        if fw_rule['ip_version'] == 4 and fw_rule['source_ip_address']:
            return str(netaddr.IPNetwork(fw_rule['source_ip_address']).cidr)
        else:
            return None

    @staticmethod
    def _map_ipv6_address_override(fw_rule):
        if fw_rule['ip_version'] == 6 and fw_rule['source_ip_address']:
            return str(netaddr.IPNetwork(fw_rule['source_ip_address']).cidr)
        else:
            return None

    @staticmethod
    def _map_network_id(fw_rule):
        if fw_rule['destination_ip_address']:
            return str(netaddr.IPNetwork(
                fw_rule['destination_ip_address']).cidr)
        else:
            return None

    @staticmethod
    def _map_network_type(fw_rule):
        if fw_rule['destination_ip_address']:
            return 'NETWORK'
        else:
            return None

    @staticmethod
    def _map_source_port(fw_rule):
        if fw_rule['source_port']:
            return fw_rule['source_port'].replace(':', '-')
        else:
            return None

    @staticmethod
    def _map_destination_port(fw_rule):
        if fw_rule['destination_port']:
            return fw_rule['destination_port'].replace(':', '-')
        else:
            return None
