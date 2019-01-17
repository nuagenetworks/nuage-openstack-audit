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
from neutron_lib import constants as lib_constants

from nuage_openstack_audit.utils.matcher import Matcher
from nuage_openstack_audit.vsdclient.common import constants


OS_ACTION_TO_VSD_ACTION = {
    'allow': 'FORWARD',
    'deny': 'DROP'
}

OS_ACTION_TO_VSD_STATEFUL = {
    'allow': True,
    'deny': False
}

OS_IPVERSION_TO_VSD_ETHERTYPE = {
    4: constants.VSP_IPV4_ETHERTYPE,
    6: constants.VSP_IPV6_ETHERTYPE
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

    def get_mapper(self):
        return {
            'source_ip_address': [
                ('address_override',
                 lambda x: str(netaddr.IPNetwork(x).cidr) if x else None)
            ],
            'name': [('description', lambda x: x)],
            'destination_ip_address': [
                ('network_id',
                    lambda x: str(netaddr.IPNetwork(x).cidr)
                    if x else None),
                ('network_type', lambda x: 'NETWORK' if x else None)
            ],
            'source_port': [
                ('source_port',
                 lambda x: x.replace(':', '-') if x else None)
            ],
            'protocol': [
                ('protocol',
                 lambda x: lib_constants.IP_PROTOCOL_MAP.get(x, 'ANY'))
            ],
            'destination_port': [
                ('destination_port', lambda x: x.replace(':', '-')
                    if x else None)
            ],
            'action': [('action',
                        lambda x: OS_ACTION_TO_VSD_ACTION[x]),
                       ('stateful',
                        lambda x: OS_ACTION_TO_VSD_STATEFUL[x])],
            'ip_version': [
                ('ether_type',
                 lambda x: OS_IPVERSION_TO_VSD_ETHERTYPE.get(x))
            ]
        }
