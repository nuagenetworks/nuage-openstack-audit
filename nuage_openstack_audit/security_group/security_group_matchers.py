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

from nuage_openstack_audit.utils.matcher import Matcher
from nuage_openstack_audit.vsdclient.common import constants


class SecurityGroupPolicyGroupMatcher(Matcher):

    def entity_name(self):
        return 'Security Group'

    def map_to_vsd_object(self, sg):
        return {
            'name': self._map_name(sg),
            'description': self._map_description(sg),
            'type': self._map_type(sg)
        }

    @staticmethod
    def _map_name(sg):
        return (sg['id'] + '_HARDWARE'
                if sg['type'] == constants.HARDWARE else sg['id'])

    @staticmethod
    def _map_description(sg):
        return sg['name']

    @staticmethod
    def _map_type(sg):
        return sg['type']


class SecurityGroupPortsPolicyGroupVportsMatcher(Matcher):
    def entity_name(self):
        return 'Security Group port'

    def get_mapper(self):
        # Only verification is external id
        return {}


class SecurityGroupRuleAclTemplateEntryMatcher(Matcher):
    """Map security group rules from Openstack to VSD

       Based on _map_nuage_sgrule in
       nuage_neutron/vsdclient/resources/policygroups.py
    """

    def __init__(self, is_stateful, acl_template_type, is_dhcp_managed,
                 is_l2_domain, policy_group_id):
        self._is_stateful = is_stateful
        assert acl_template_type in [constants.HARDWARE, constants.SOFTWARE]
        self._is_hardware = acl_template_type == constants.HARDWARE
        self._is_dhcp_managed = is_dhcp_managed
        self._is_l2_domain = is_l2_domain
        self._policy_group_id = policy_group_id

    def entity_name(self):
        return 'Security Group Rule'

    def map_to_vsd_object(self, sg_rule):
        # common attributes
        vsd_obj = {
            'ether_type': self._map_ethertype(sg_rule),
            'protocol': self._map_protocol(sg_rule),
            'stateful': self._map_stateful(sg_rule),
            'network_type': self._map_network_type(sg_rule),
            'location_type': self._map_location_type(sg_rule),
            'location_id': self._map_location_id(sg_rule),
            'action': self._map_action(sg_rule),
            'dscp': self._map_dscp(sg_rule),
            # 'networkID': self._map_network_id(sg_rule)  #TODO VSD call?
        }

        # TCP and UDP attributes
        if sg_rule['protocol'] in ['tcp', 'udp']:
            vsd_obj.update({
                'source_port': self._map_source_port(sg_rule),
                'destination_port': self._map_destination_port(sg_rule)
            })

        # ICMP attributes
        elif sg_rule['protocol'] == 'icmp':
            if sg_rule['port_range_min']:
                vsd_obj['icmp_type'] = self._map_icmp_type(sg_rule)
            elif sg_rule['port_range_max']:
                vsd_obj['icmp_code'] = self._map_icmp_code(sg_rule)

        # Return created VSD object
        return vsd_obj

    @staticmethod
    def _map_source_port(_):
        return '*'

    @staticmethod
    def _map_destination_port(neutron_obj):
        if (not neutron_obj['port_range_min'] or
                not neutron_obj['port_range_max']):
            return '*'
        if neutron_obj['port_range_min'] == neutron_obj['port_range_max']:
            return neutron_obj['port_range_min']
        else:
            return '{}-{}'.format(neutron_obj['port_range_min'],
                                  neutron_obj['port_range_max'])

    @staticmethod
    def _map_icmp_type(neutron_obj):
        assert neutron_obj['port_range_min']
        return str(neutron_obj['port_range_min'])

    @staticmethod
    def _map_icmp_code(neutron_obj):
        assert neutron_obj['port_range_max']
        return str(neutron_obj['port_range_max'])

    def _map_network_id(self, neutron_obj):
        # TODO VSD calls needed
        pass

    @staticmethod
    def _map_dscp(_):
        return '*'

    @staticmethod
    def _map_action(_):
        return 'FORWARD'

    def _map_location_id(self, _):
        return self._policy_group_id

    @staticmethod
    def _map_location_type(_):
        return 'POLICYGROUP'

    def _map_network_type(self, neutron_obj):
        if 'remote_ip_prefix' in neutron_obj:
            return 'ENTERPRISE_NETWORK'
        elif ('remote_group_id' in neutron_obj or
                'remote_external_group' in neutron_obj):
            return 'POLICYGROUP'
        elif ((self._is_l2_domain and self._is_dhcp_managed) or
              self._is_hardware):
            return 'ANY'
        else:
            return 'ENDPOINT_DOMAIN'

    def _map_stateful(self, neutron_obj):
        if self._is_hardware:
            return False
        elif (neutron_obj['protocol'] == 'icmp' and (
                (not str(neutron_obj['port_range_max']) and not
                 str(neutron_obj['port_range_min'])) or
                neutron_obj['port_range_min'] not in
                constants.STATEFUL_ICMP_TYPES)):
            return False
        else:
            return self._is_stateful

    @staticmethod
    def _map_ethertype(neutron_obj):
        if neutron_obj['ethertype'] == constants.OS_IPV4_ETHERTYPE:
            return constants.VSP_IPV4_ETHERTYPE
        elif neutron_obj['ethertype'] == constants.OS_IPV6_ETHERTYPE:
            return constants.VSP_IPV6_ETHERTYPE
        else:
            return None

    @staticmethod
    def _map_protocol(neutron_obj):
        try:
            return int(neutron_obj['protocol'])
        except (ValueError, TypeError):
            # protocol passed in rule create is a string
            protocol = str(neutron_obj['protocol'])
            if not neutron_obj['protocol']:
                protocol = 'ANY'
            if protocol != 'ANY':
                if protocol == 'icmp' and neutron_obj['ethertype'] == \
                        constants.OS_IPV6_ETHERTYPE:
                    protocol = 'icmpv6'
                protocol = constants.PROTOCOL_NAME_TO_NUM[protocol]
            return protocol
