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

import logging

import netaddr

from nuage_openstack_audit.vsdclient.common import constants
from nuage_openstack_audit.vsdclient.common.vspk_helper import VspkHelper

LOG = logging.getLogger(__name__)


class SecurityGroupsMixin(object):

    def __init__(self, vspk_helper):
        self.vspk_helper = vspk_helper

    def get_domains(self, ent=None, vspk_filter=None):
        for fetcher_str in ['domains', 'l2_domains']:
            domains = VspkHelper.get_all(
                parent=self.vspk_helper.get_default_enterprise()
                if ent is None else ent,
                filter=vspk_filter,
                fetcher_str=fetcher_str)
            for domain in domains:
                yield domain

    def get_ingress_acl_entries(self, by_domain=None,
                                by_policy_group_id=None,
                                cms_id=None):
        if not by_domain:
            raise NotImplementedError

        kwargs = self.get_acl_entry_filter(by_policy_group_id, cms_id)

        return VspkHelper.get_all(by_domain, "ingress_acl_entry_templates",
                                  **kwargs)

    @staticmethod
    def get_acl_entry_filter(by_policy_group_id, cms_id):
        if by_policy_group_id:
            vspk_filter = ('locationType IS "POLICYGROUP" AND '
                           'locationID IS "{}" '.format(by_policy_group_id))
            if cms_id:
                vspk_filter += " AND externalID ENDSWITH '@{}'".format(cms_id)
        elif cms_id:
            vspk_filter = "externalID ENDSWITH '@{}'".format(cms_id)
        kwargs = {'filter': vspk_filter} if vspk_filter else {}
        return kwargs

    def get_egress_acl_templates_by_external_id(self, domain, external_id):
        kwargs = {'filter':
                  self.vspk_helper.get_external_id_filter(external_id)}

        return VspkHelper.get_all(domain, "egress_acl_templates", **kwargs)

    @staticmethod
    def get_egress_acl_entries_by_acl(acl):
        return VspkHelper.get_all(acl, "egress_acl_entry_templates")

    def get_egress_acl_entries(self, by_domain=None,
                               by_policy_group_id=None,
                               cms_id=None):
        if not by_domain:
            raise NotImplementedError

        kwargs = self.get_acl_entry_filter(by_policy_group_id, cms_id)

        return VspkHelper.get_all(by_domain, "egress_acl_entry_templates",
                                  **kwargs)

    def get_l3domain(self, enterprise=None, vspk_filter=None,
                     by_neutron_id=None):
        if not enterprise:
            enterprise = self.vspk_helper.get_default_enterprise()

        if by_neutron_id:
            return self.get_l3domain(
                enterprise,
                vspk_filter=self.vspk_helper.get_external_id_filter(
                    by_neutron_id))
        else:
            return enterprise.domains.get_first(filter=vspk_filter)

    def get_l2domain(self, enterprise=None, vspk_filter=None,
                     by_network_id=None, by_cidr=None, by_subnet=None,
                     ip_type=4):
        if not enterprise:
            enterprise = self.vspk_helper.get_default_enterprise()
        if vspk_filter:
            l2_domain = enterprise.l2_domains.get_first(filter=vspk_filter)
        elif by_subnet:
            return self.get_l2domain(enterprise, vspk_filter,
                                     by_network_id=by_subnet['network_id'],
                                     by_cidr=by_subnet['cidr'],
                                     ip_type=by_subnet['ip_version'])
        elif by_network_id and by_cidr:
            if ip_type == 6:
                vspk_filter = self.vspk_helper.get_vsd_filter(
                    ['externalID', 'IPv6Address'],
                    [self.vspk_helper.get_external_id(by_network_id), by_cidr])
                l2_domain = self.get_l2domain(enterprise, vspk_filter)
            else:
                vspk_filter = self.vspk_helper.get_vsd_filter(
                    ['externalID', 'address'],
                    [self.vspk_helper.get_external_id(by_network_id),
                     by_cidr.split('/')[0]])
                l2_domain = self.get_l2domain(enterprise, vspk_filter)
        else:
            LOG.error('a qualifier is required')
            return None
        if not l2_domain:
            LOG.warning('could not fetch the l2 domain '
                        'matching the filter "{}"'.format(vspk_filter))
        return l2_domain

    def get_vports(self, parent, vspk_filter=None):
        return VspkHelper.get_all(
            parent=parent,
            filter=vspk_filter,
            fetcher_str="vports")

    @staticmethod
    def get_policy_groups(domain, vspk_filter=None):
        return VspkHelper.get_all(
            parent=domain,
            filter=vspk_filter,
            fetcher_str="policy_groups")

    def get_policy_group(self, domain, vspk_filter=None, by_neutron_id=None):
        if by_neutron_id:
            return self.get_policy_group(
                domain,
                vspk_filter=self.vspk_helper.get_external_id_filter(
                    by_neutron_id))
        else:
            return domain.policy_groups.get_first(filter=vspk_filter)

    def get_enterprise_network_id(self, ethertype, remote_ip_prefix):
        assert ethertype in [constants.OS_IPV4_ETHERTYPE,
                             constants.OS_IPV6_ETHERTYPE]
        try:
            ip_network = netaddr.IPNetwork(remote_ip_prefix)
        except netaddr.AddrFormatError:
            LOG.debug('Unable to get enterprise network id bacause of invalid'
                      ' remote ip prefix argument')
            return None
        else:
            enterprise_network = self.get_enterprise_network(ip_network)
            return enterprise_network.id if enterprise_network else None

    def get_enterprise_network(self, ip_network, enterprise=None):
        if not enterprise:
            enterprise = self.vspk_helper.get_default_enterprise()

        assert ip_network.version in [4, 6]
        if ip_network.version == 4:
            return enterprise.enterprise_networks.get_first(
                filter='address IS "{}" and netmask IS "{}"'
                       .format(ip_network.ip, ip_network.netmask))
        else:
            return enterprise.enterprise_networks.get_first(
                filter='IPv6Address IS "{}"'.format(ip_network))
