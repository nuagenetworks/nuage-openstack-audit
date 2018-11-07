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


class HardwarePGAudit(Audit):

    def __init__(self, neutron, vsd, cms_id):
        super(HardwarePGAudit, self).__init__(cms_id)

        self.neutron = neutron
        self.vsd = vsd

        self.audit_report = []
        self.cnt_in_sync = 0

    def audit_default_block_all_acl(self, domain, os_id):
        """A block all acl with lowest priority should exist"""
        acls = list(self.vsd.get_egress_acl_templates_by_external_id(
            domain, external_id='hw:{}'.format(os_id)))
        acls_cnt = len(acls)

        # No acls
        if acls_cnt == 0:
            self.audit_report.append({
                'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                'entity_type': 'Router',
                'neutron_entity': os_id,
                'vsd_entity': None,
                'discrepancy_details': 'Missing hardware block-all ACL.'
            })
            return False

        # Too many acls
        if acls_cnt > 1:
            acls.sort(key=lambda x: x.priority)
            for orphan in acls[1:]:
                self.audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': 'Egress ACL template',
                    'neutron_entity': os_id,
                    'vsd_entity': orphan.id,
                    'discrepancy_details': 'Duplicate hardware block-all '
                                           'ACL.'})

        acl_entries = list(self.vsd.get_egress_acl_entries_by_acl(acls[0]))
        acl_entries_cnt = len(acl_entries)

        # No entries
        if acl_entries_cnt == 0:
            self.audit_report.append({
                'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                'entity_type': 'ACL template entry',
                'neutron_entity': os_id,
                'vsd_entity': acls[0].id,
                'discrepancy_details': 'Missing acl_template_entry for'
                                       'hardware block all ACL.'})
            return False

        # Too many entries
        if acl_entries_cnt > 1:
            acl_entries.sort(key=lambda x: x.priority)
            for orphan in acl_entries[1:]:
                self.audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': 'ACL template entry',
                    'neutron_entity': os_id,
                    'vsd_entity': orphan.id,
                    'discrepancy_details': 'Hardware block-all ACL '
                                           'has more than one rule'})

        # Check the acl entry with highest priority
        entry = acl_entries[0]
        # TODO(vandewat) check other stuff as well
        if (entry.protocol != 'ANY' or entry.action != 'DROP' or
                entry.network_type != 'ANY'):
            self.audit_report.append({
                'discrepancy_type': 'ENTITY_MISMATCH',
                'entity_type': 'ACL template entry',
                'neutron_entity': os_id,
                'vsd_entity': entry.id,
                'discrepancy_details': 'Invalid rule for hardware block-all '
                                       'acl'
            })
            return False
        self.cnt_in_sync += 1
        return True

    def audit(self, domain, os_id):
        self.audit_report = []
        self.audit_default_block_all_acl(domain, os_id)
        return self.audit_report, self.cnt_in_sync
