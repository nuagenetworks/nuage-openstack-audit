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

from nuage_openstack_audit.vsdclient.common.cms_id_helper import \
    get_vsd_external_id
from nuage_openstack_audit.vsdclient.common import constants
from nuage_openstack_audit.vsdclient.common.helper import get_by_field_values
from nuage_openstack_audit.vsdclient.common.nuagelib import Domain
from nuage_openstack_audit.vsdclient.common.nuagelib import FirewallAcl
from nuage_openstack_audit.vsdclient.common.nuagelib import FirewallRule
from nuage_openstack_audit.vsdclient import restproxy

LOG = logging.getLogger(__name__)

OS_ACTION_TO_VSD_ACTION = {
    'allow': 'FORWARD',
    'deny': 'DROP'
}
OS_ACTION_TO_VSD_STATEFUL = {
    'allow': True,
    'deny': False
}
OS_IPVERSION_TO_VSD_ETHERTYPE = {
    4: constants.IPV4_ETHERTYPE,
    6: constants.IPV6_ETHERTYPE
}


def copy(value):
    return value


class NuageFwaasBase(object):

    def __init__(self, restproxy):
        super(NuageFwaasBase, self).__init__()
        self.restproxy = restproxy

    def _vsd_fw_rule_by_os_id(self, enterprise_id, id, required=False):
        return self._get_by_openstack_id(
            FirewallRule, id, parent='enterprises', parent_id=enterprise_id,
            required=required)

    def _vsd_fw_acl_by_os_id(self, enterprise_id, id, required=False):
        return self._get_by_openstack_id(
            FirewallAcl, id, parent='enterprises', parent_id=enterprise_id,
            required=required)

    def _get_by_openstack_id(self, resource, id, parent=None, parent_id=None,
                             required=False):
        external_id = get_vsd_external_id(id)
        filter_header = FirewallRule.extra_header_filter(
            externalID=external_id)
        objects = self.get(resource, parent=parent, parent_id=parent_id,
                           extra_headers=filter_header)
        if not objects and required:
            raise restproxy.ResourceNotFoundException(
                "Can not find %s with externalID %s on vsd"
                % (resource.resource, external_id))
        return objects[0] if objects else None

    def get(self, resource, parent=None, parent_id=None, extra_headers=None):
        return self.restproxy.get(
            resource.get_url(parent=parent, parent_id=parent_id),
            extra_headers=extra_headers)


class NuageFwaas(NuageFwaasBase):

    def get_firewall_rules(self, enterprise_id):
        return self.get(FirewallRule, parent='enterprises',
                        parent_id=enterprise_id)

    def get_firewall_rules_by_ids(self, enterprise_id, os_rule_ids):
        external_ids = [get_vsd_external_id(os_id) for os_id in os_rule_ids]
        return get_by_field_values(self.restproxy, FirewallRule,
                                   'externalID', external_ids,
                                   parent='enterprises',
                                   parent_id=enterprise_id)

    def get_firewall_rules_by_os_policy(self, enterprise_id, os_policy_id):
        external_id = get_vsd_external_id(os_policy_id)
        acls = get_by_field_values(self.restproxy, FirewallAcl,
                                   'externalID', [external_id],
                                   parent='enterprises',
                                   parent_id=enterprise_id)
        acl = next(acls)
        return self.get(FirewallRule, parent='firewallacls',
                        parent_id=acl['ID']) if acl else []

    def get_firewall_acls(self, enterprise_id):
        return self.get(FirewallAcl, parent='enterprises',
                        parent_id=enterprise_id)

    def get_firewalls(self, enterprise_id):
        Firewall = namedtuple('Firewall', 'policyID, domainID')
        acls = (acl for acl in self.get_firewall_acls(enterprise_id)
                if acl.get('externalID'))
        return [Firewall(acl['externalID'], domain['externalID'])
                for acl in acls
                for domain in self.get(Domain, parent='firewallacls',
                                       parent_id=acl['ID'])
                if domain and domain.get('externalID')]
