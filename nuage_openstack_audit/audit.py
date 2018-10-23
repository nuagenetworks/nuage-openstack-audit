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

from __future__ import print_function

import abc
import six

from nuage_openstack_audit.utils.entity_tracker import tracked
from nuage_openstack_audit.utils.logger import Reporter

INFO = Reporter('INFO')


class Audit(object):

    @staticmethod
    def strip_cms_id(external_id):
        return external_id.split('@')[0] if external_id else external_id

    @staticmethod
    def vsd_entity_to_neutron_id(vsd_entity):
        return Audit.strip_cms_id(vsd_entity.external_id)

    def audit_entities(self, audit_report,
                       neutron_entities,
                       vsd_entities,
                       entity_matcher,
                       excluded_vsd_entity=None,
                       expected_neutron_orphan=None):
        """Audit a set of neutron/vsd entities.

        :param audit_report: the audit report to report to
        :param neutron_entities: iterable of neutron entities under audit
        :param vsd_entities: iterable of vsd entities under audit
        :param entity_matcher: matcher used for entity comparisons
        :param excluded_vsd_entity: function pointer used to exclude
               entities from the VSD audit. If None, not applicable.
        :param expected_neutron_orphan: function pointer used to exclude
               entities from the neutron orphan audit. If None, not applicable.
        :return dict of neutron entity ids to vsd ids
        """
        initial_audit_report_len = len(audit_report)
        neutron_entity_ids_to_vsd_ids = {}

        v_entities = tracked('vsd entities')
        n_entities = tracked('neutron entities', neutron_entities)
        n_in_syncs = tracked('neutron in syncs entities')
        n_mismatches = tracked('neutron mismatch entities')
        n_expected_orphans = tracked('neutron orphan-by-design entities')
        n_orphans = tracked('neutron orphan entities')
        v_orphans = tracked('vsd orphan entities')

        neutron_ids_to_obj = dict([(n['id'], n) for n in neutron_entities])

        for v in vsd_entities:
            if excluded_vsd_entity and excluded_vsd_entity(v):
                continue

            v_entities += v
            n_id = self.vsd_entity_to_neutron_id(v)
            neutron_entity_ids_to_vsd_ids[n_id] = v.id

            n = neutron_ids_to_obj.get(n_id)
            if n:
                attr_discrepancies = entity_matcher.compare(n, v)
                if not attr_discrepancies:
                    n_in_syncs += n
                else:
                    discrepancy_details = ','.join(
                        str(d) for d in attr_discrepancies)
                    audit_report.append({
                        'discrepancy_type': 'ENTITY_MISMATCH',
                        'entity_type': entity_matcher.entity_name(),
                        'neutron_entity': n_id,
                        'vsd_entity': v.id,
                        'discrepancy_details': discrepancy_details})
                    n_mismatches += n
                del neutron_ids_to_obj[n_id]
            else:
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': entity_matcher.entity_name(),
                    'neutron_entity': None,
                    'vsd_entity': v.id,
                    'discrepancy_details': 'N/A'})
                v_orphans += v

        # neutron_ids_set is unconfirmed set of neutron id's now
        for n_id, n in six.iteritems(neutron_ids_to_obj):
            neutron_entity_ids_to_vsd_ids[n_id] = None

            if expected_neutron_orphan and expected_neutron_orphan(n):
                n_expected_orphans += n
            else:
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                    'entity_type': entity_matcher.entity_name(),
                    'neutron_entity': n_id,
                    'vsd_entity': None,
                    'discrepancy_details': 'N/A'})
                n_orphans += n

        v_entities.report()  # audited entities
        n_entities.report()
        n_in_syncs.report()
        n_mismatches.report()
        n_expected_orphans.report()
        n_orphans.report()
        v_orphans.report()

        INFO.h2('%d discrepancies reported',
                len(audit_report) - initial_audit_report_len)

        return neutron_entity_ids_to_vsd_ids

    @abc.abstractmethod
    def audit(self, audit_report):
        pass
