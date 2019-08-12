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

from collections import Counter

from nuage_openstack_audit.audit import Audit
from nuage_openstack_audit.security_group.security_group_matchers \
    import SecurityGroupPortsPolicyGroupVportsMatcher
from nuage_openstack_audit.utils.logger import Reporter
import nuage_openstack_audit.vsdclient.common.constants as constants

INFO = Reporter('INFO')


class PGAllowAllAudit(Audit):

    def __init__(self, neutron, vsd, cms_id, ignore_vsd_orphans):
        super(PGAllowAllAudit, self).__init__(cms_id, ignore_vsd_orphans)

        self.neutron = neutron
        self.vsd = vsd
        self.audit_report = []
        self.cnt_in_sync = Counter()

    def audit(self, domain, pg_allow_all, ports):

        self.audit_report = []
        self.cnt_in_sync = Counter()

        # Audit PG
        # audit ingress entries
        self._audit_acl_entries(
            domain, 'ingress_acl_entry_templates',
            self.vsd.get_ingress_acl_entries, pg_allow_all.id)
        # audit egress entries
        self._audit_acl_entries(
            domain, 'egress_acl_entry_templates',
            self.vsd.get_egress_acl_entries, pg_allow_all.id)
        vports = self.vsd.get_vports(pg_allow_all)
        self.cnt_in_sync['vports (PG_ALLOW_ALL)'] += self.audit_entities(
            self.audit_report, ports, vports,
            SecurityGroupPortsPolicyGroupVportsMatcher(),
            report_tracked_entities=False)

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
                    'discrepancy_details': 'PG_ALLOW_ALL ACL has an entry '
                                           'with invalid ether_type'
                })

        # IPV4: Check that there is a sole entry which is allowing all traffic
        self._check_sole_allow_all_entry(acl_entries_ipv4, entity_type,
                                         policygroup_id,
                                         constants.OS_IPV4_ETHERTYPE)
        # IPV6: Check that there is a sole entry which is allowing all traffic
        self._check_sole_allow_all_entry(acl_entries_ipv6, entity_type,
                                         policygroup_id,
                                         constants.OS_IPV6_ETHERTYPE)

    def _check_sole_allow_all_entry(self, acl_entries, entity_type_name,
                                    policygroup_id, ether_type):
        entry_cnt = len(acl_entries)

        # No entries
        if entry_cnt == 0:
            self.audit_report.append({
                'discrepancy_type': 'ENTITY_MISMATCH',
                'entity_type': 'policy group',
                'neutron_entity': None,
                'vsd_entity': policygroup_id,
                'discrepancy_details': 'PG_ALLOW_ALL ACL has missing entries '
                                       'for {}'.format(ether_type)})
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
                    'discrepancy_details': 'PG_ALLOW_ALL ACL has too many '
                                           'entries '
                                           'for {}'.format(ether_type)})

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
                'discrepancy_details': 'Invalid {} entry in policy group for '
                                       'PG_ALLOW_ALL ACL'.format(ether_type)
            })
        else:
            self.cnt_in_sync['{} (PG_ALLOW_ALL)'.format(entity_type_name)] += 1
