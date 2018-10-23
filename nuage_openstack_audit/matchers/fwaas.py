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

from nuage_openstack_audit.matchers.base import Matcher


IPV4_ETHERTYPE = '0x0800'
IPV6_ETHERTYPE = '0x86DD'

PROTO_NAME_TO_NUM = {
    'tcp': 6,
    'udp': 17,
    'icmp': 1,
    'icmpv6': 58
}

OS_ACTION_TO_VSD_ACTION = {
    'allow': 'FORWARD',
    'deny': 'DROP'
}

OS_ACTION_TO_VSD_STATEFUL = {
    'allow': True,
    'deny': False
}

OS_IPVERSION_TO_VSD_ETHERTYPE = {
    4: IPV4_ETHERTYPE,
    6: IPV6_ETHERTYPE
}


def copy(value):
    return value


class FirewallPolicyMatcher(Matcher):

    def entity_name(self):
        return 'Firewall policy'

    def get_mapper(self):
        return {
            'name': [('name', copy)],
            'description': [('description', copy)]
        }


class FirewallRuleMatcher(Matcher):

    def entity_name(self):
        return 'Firewall rule'

    def get_mapper(self):
        return {
            'source_ip_address': [
                ('addressOverride',
                 lambda x: str(netaddr.IPNetwork(x).cidr) if x else None)
            ],
            'name': [('description', copy)],
            'destination_ip_address': [
                ('networkID',
                    lambda x: str(netaddr.IPNetwork(x).cidr) if x else None),
                ('networkType', lambda x: 'NETWORK' if x else None)
            ],
            'source_port': [
                ('sourcePort', lambda x: x.replace(':', '-') if x else None)
            ],
            'protocol': [
                ('protocol', lambda x: PROTO_NAME_TO_NUM.get(x, 'ANY'))
            ],
            'destination_port': [
                ('destinationPort', lambda x: x.replace(':', '-')
                    if x else None)
            ],
            'action': [('action', lambda x: OS_ACTION_TO_VSD_ACTION[x]),
                       ('stateful', lambda x: OS_ACTION_TO_VSD_STATEFUL[x])],
            'ip_version': [
                ('etherType', lambda x: OS_IPVERSION_TO_VSD_ETHERTYPE.get(x))
            ]
        }
