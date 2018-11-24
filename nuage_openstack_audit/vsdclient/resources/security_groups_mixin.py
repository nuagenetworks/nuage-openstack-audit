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

from nuage_openstack_audit.vsdclient.common.vspk_helper import VspkHelper

LOG = logging.getLogger(__name__)


class SecurityGroupsMixin(object):

    def __init__(self, vspk_helper):
        self.vspk_helper = vspk_helper

    def get_domains(self, ent=None, vspk_filter=None):
        return VspkHelper.get_all(
            parent=self.vspk_helper.get_default_enterprise()
            if ent is None else ent,
            filter=vspk_filter,
            fetcher_str="domains")

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
                     by_neutron_id=None):
        if not enterprise:
            enterprise = self.vspk_helper.get_default_enterprise()

        if by_neutron_id:
            return self.get_l2domain(
                enterprise,
                vspk_filter=self.vspk_helper.get_external_id_filter(
                    by_neutron_id))
        else:
            return enterprise.l2_domains.get_first(filter=vspk_filter)

    def get_vports(self, parent=None, vspk_filter=None):
        return VspkHelper.get_all(
            parent=self.vspk_helper.get_default_enterprise()
            if parent is None else parent,
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
