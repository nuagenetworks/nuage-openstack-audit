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

from nuage_openstack_audit.audit import Audit
import nuage_openstack_audit.vsdclient.common.constants as constants
from nuage_openstack_audit.security_group.security_group_matchers \
    import SecurityGroupPortsPolicyGroupVportsMatcher


class PGForLessAudit(Audit):

    def __init__(self, neutron, vsd, cms_id):
        super(PGForLessAudit, self).__init__(cms_id)

        self.neutron = neutron
        self.vsd = vsd
        self.audit_report = []
        self.cnt_in_sync = 0

    def audit(self, domain, policygroups, ports):

        self.audit_report = []
        self.cnt_in_sync = 0

        nr_policygroups = len(policygroups)
        if nr_policygroups == 0:
            for port in ports:
                self.audit_report.append({
                    'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                    'entity_type': 'port',
                    'neutron_entity': port['id'],
                    'vsd_entity': None,
                    'discrepancy_details': 'No Policy Group for less security '
                                           'found while ports with no port '
                                           'security exist.'})

        vports = []
        for pg in policygroups:
            # Audit PG
            # audit ingress entries
            self._audit_acl_entries(
                domain, 'ingress_acl_entry_templates',
                self.vsd.get_ingress_acl_entries, pg.id)
            # audit egress entries
            self._audit_acl_entries(
                domain, 'egress_acl_entry_templates',
                self.vsd.get_egress_acl_entries, pg.id)
            vports.extend(self.vsd.get_vports(pg))
        self.cnt_in_sync += self.audit_entities(
            self.audit_report, ports, vports,
            SecurityGroupPortsPolicyGroupVportsMatcher())

        return self.audit_report, self.cnt_in_sync

    def _audit_acl_entries(self, domain, entity_type,
                           entry_provider, policygroup_id):
        # split entries in IPV4, IPV6
        acl_entries_ipv4 = []
        acl_entries_ipv6 = []
        for entry in entry_provider(by_domain=domain,
                                    by_policy_group_id=policygroup_id):
            if entry.ether_type == constants.VSP_IPV4_ETHERTYPE:
                acl_entries_ipv4.append(entry)
            elif entry.ether_type == constants.VSP_IPV6_ETHERTYPE:
                acl_entries_ipv6.append(entry)
            else:
                self.audit_report.append({
                    'discrepancy_type': 'ENTITY_MISMATCH',
                    'entity_type': entity_type,
                    'neutron_entity': None,
                    'vsd_entity': entry.id,
                    'discrepancy_details': 'Invalid ether_type'
                })

        # IPV4: Check that there is a sole entry which is allowing all traffic
        self._check_sole_allow_all_entry(acl_entries_ipv4, entity_type,
                                         policygroup_id)
        # IPV6: Check that there is a sole entry which is allowing all traffic
        self._check_sole_allow_all_entry(acl_entries_ipv6, entity_type,
                                         policygroup_id)

    def _check_sole_allow_all_entry(self, acl_entries, entity_type_name,
                                    policygroup_id):
        entry_cnt = len(acl_entries)

        # No entries
        if entry_cnt == 0:
            self.audit_report.append({
                'discrepancy_type': 'ENTITY_MISMATCH',
                'entity_type': 'policy group',
                'neutron_entity': None,
                'vsd_entity': policygroup_id,
                'discrepancy_details': 'Policy group for less security '
                                       'has missing rules'})
            return

        # Too many entries
        elif entry_cnt > 1:
            acl_entries.sort(key=lambda x: x.priority)
            for orphan in acl_entries[1:]:
                self.audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': entity_type_name,
                    'neutron_entity': None,
                    'vsd_entity': orphan.id,
                    'discrepancy_details': 'Policy group for less security '
                                           'has too many rules'})

        # Check the acl entry with highest priority
        entry = acl_entries[0]
        if (entry.location_type != 'POLICYGROUP' or
                entry.network_type != 'ANY' or
                entry.protocol != 'ANY' or
                entry.action != 'FORWARD' or
                entry.dscp != '*'):
            self.audit_report.append({
                'discrepancy_type': 'ENTITY_MISMATCH',
                'entity_type': entity_type_name,
                'neutron_entity': None,
                'vsd_entity': entry.id,
                'discrepancy_details': 'Invalid rule'
            })
        else:
            self.cnt_in_sync += 1
