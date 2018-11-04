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

from collections import namedtuple
import logging

from nuage_openstack_audit.vsdclient.common.vspk_helper import VspkHelper

LOG = logging.getLogger(__name__)


class FWaaSMixin(object):

    def __init__(self, vspk_helper):
        self.vspk_helper = vspk_helper

    def get_firewall_acl(self, ent=None, vspk_filter=None,
                         by_fw_policy_id=None):
        """get a firewall acl.

        @params: enterprise object
                 vspk_filter following vspk filter structure
        @return: firewall_acl object
        @Example:
        self.vsd.get_firewall_acl(ent=ent1,
            vspk_filter='externalID == "{}"'.format(ext_id))
        """
        if vspk_filter:
            if ent and not isinstance(ent, self.vspk_helper.vspk.NUEnterprise):
                LOG.error('a enterprise is required')
                return None
            else:
                ent = self.vspk_helper.get_default_enterprise()
            firewall_acl = ent.firewall_acls.get_first(filter=vspk_filter)
        elif by_fw_policy_id:
            firewall_acl = self.get_firewall_acl(
                ent, self.vspk_helper.get_external_id_filter(by_fw_policy_id))
        else:
            LOG.error('a qualifier is required')
            return None

        if not firewall_acl:
            LOG.warning('could not fetch the firewall_acl matching '
                        'the filter "{}"'.format(vspk_filter))
        return firewall_acl

    def get_firewall_rule(self, ent=None, vspk_filter=None,
                          by_fw_rule_id=None):
        """get a firewall rule.

        @params: enterprise object
                 vspk_filter following vspk filter structure
        @return: get_firewall_rule object
        @Example:
        self.vsd.get_firewall_rule(ent=ent1,
            vspk_filter='externalID == "{}"'.format(ext_id))
        """
        if vspk_filter:
            if ent:
                if not isinstance(ent, self.vspk_helper.vspk.NUEnterprise):
                    LOG.error('a enterprise is required')
                    return None
            else:
                ent = self.vspk_helper.get_default_enterprise()
            firewall_rule = ent.firewall_rules.get_first(filter=vspk_filter)
        elif by_fw_rule_id:
            firewall_rule = self.get_firewall_rule(
                ent, self.vspk_helper.get_external_id_filter(by_fw_rule_id))
        else:
            LOG.error('a qualifier is required')
            return None

        if not firewall_rule:
            LOG.warning('could not fetch the firewall_rule matching '
                        'the filter "{}"'.format(vspk_filter))
        return firewall_rule

    def get_firewall_acls(self, ent=None, vspk_filter=None):
        return VspkHelper.get_all(
            parent=self.vspk_helper.get_default_enterprise()
            if ent is None else ent,
            filter=vspk_filter,
            fetcher_str="firewall_acls")

    def get_firewall_rules(self, ent=None):
        return VspkHelper.get_all(
            parent=self.vspk_helper.get_default_enterprise()
            if ent is None else ent,
            fetcher_str="firewall_rules")

    def get_firewall_rules_by_ids(self, ent=None, os_rule_ids=None):
        if os_rule_ids is None:
            os_rule_ids = []
        return VspkHelper.get_all_by_field(
            parent=self.vspk_helper.get_default_enterprise()
            if ent is None else ent,
            fetcher_str="firewall_rules",
            field_name='externalID',
            field_values=[self.vspk_helper.get_external_id(os_id)
                          for os_id in os_rule_ids])

    def get_firewall_rules_by_policy(self, ent=None, os_policy_id=None):
        acl = self.get_firewall_acl(ent=ent, by_fw_policy_id=os_policy_id)
        if acl:
            for acl in VspkHelper.get_all(
                    parent=acl,
                    fetcher_str="firewall_rules"):
                yield acl
        else:
            LOG.warning('could not fetch the firewall_acl matching '
                        'the os policy id "{}"'.format(os_policy_id))

    def get_firewalls(self, ent=None):
        Firewall = namedtuple(
            'Firewall', 'acl_id acl_external_id domain_id domain_external_id')
        return (Firewall(acl_id=acl.id,
                         acl_external_id=acl.external_id,
                         domain_id=domain.id,
                         domain_external_id=domain.external_id)
                for acl in self.get_firewall_acls(ent=ent)
                for domain in VspkHelper.get_all(acl, "domains")
                if domain.external_id)
