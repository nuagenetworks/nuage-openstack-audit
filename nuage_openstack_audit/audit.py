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

import abc
from recordclass import recordclass
import six

from nuage_openstack_audit.utils.entity_tracker import tracked
from nuage_openstack_audit.utils.logger import Reporter

INFO = Reporter('INFO')
DEBUG = Reporter('DEBUG')


class Audit(object):

    @staticmethod
    def strip_cms_id(external_id):
        return external_id.split('@')[0] if external_id else external_id

    @staticmethod
    def vsd_entity_to_neutron_id(vsd_entity):
        return Audit.strip_cms_id(vsd_entity.external_id)

    EntityTracker = recordclass(
        'EntityTracker', 'v_entities v_excluded_entities n_entities '
                         'n_in_syncs n_mismatches n_expected_orphans '
                         'n_orphans v_orphans')

    @staticmethod
    def get_audit_entity_tracker(n_entities=None,
                                 v_entities=None,
                                 v_excluded_entities=None,
                                 n_in_syncs=None,
                                 n_mismatches=None,
                                 n_expected_orphans=None,
                                 n_orphans=None,
                                 v_orphans=None):
        return Audit.EntityTracker(
            n_entities=(n_entities if n_entities
                        else tracked('neutron entities')),
            v_entities=(v_entities if v_entities
                        else tracked('vsd entities')),
            v_excluded_entities=(v_excluded_entities if v_excluded_entities
                                 else tracked('vsd excluded entities')),
            n_in_syncs=(n_in_syncs if n_in_syncs
                        else tracked('neutron/vsd in syncs entities')),
            n_mismatches=(n_mismatches if n_mismatches
                          else tracked('neutron mismatch entities')),
            n_expected_orphans=(n_expected_orphans if n_expected_orphans
                                else tracked('neutron orphan-by-design '
                                             'entities')),
            n_orphans=(n_orphans if n_orphans
                       else tracked('neutron orphan entities')),
            v_orphans=(v_orphans if v_orphans
                       else tracked('vsd orphan entities')))

    def audit_entities(self, audit_report,
                       neutron_entities,
                       vsd_entities,
                       entity_matcher,
                       excluded_vsd_entity=None,
                       expected_neutron_orphan=None,
                       neutron_id_to_vsd_ids_dict=None):
        """Audit a set of neutron/vsd entities.

        :param audit_report: the audit report to report to
        :param neutron_entities: iterable of neutron entities under audit
        :param vsd_entities: iterable of vsd entities under audit
        :param entity_matcher: matcher used for entity comparisons
        :param excluded_vsd_entity: function used to exclude entities from
               the VSD audit. If None, not applicable.
        :param expected_neutron_orphan: function used to exclude entities from
               the neutron orphan audit. If None, not applicable.
        :param neutron_id_to_vsd_ids_dict: if passed, this dict is filled with
               neutron id to vsd id mappings
        :return number entities in sync
        """
        DEBUG.h2('====== audit_entities (%s) ======',
                 entity_matcher.__class__.__name__)

        initial_audit_report_len = len(audit_report)

        entity_tracker = self.get_audit_entity_tracker(
            n_entities=tracked('neutron entities', neutron_entities))

        neutron_ids_to_obj = dict([(n['id'], n) for n in neutron_entities])

        for v in vsd_entities:
            if excluded_vsd_entity and excluded_vsd_entity(v):
                entity_tracker.v_excluded_entities += v
                continue

            entity_tracker.v_entities += v
            n_id = self.vsd_entity_to_neutron_id(v)

            n = neutron_ids_to_obj.get(n_id)
            if n:
                if neutron_id_to_vsd_ids_dict is not None:
                    neutron_id_to_vsd_ids_dict[n_id] = v.id

                attr_discrepancies = entity_matcher.compare(n, v)
                if not attr_discrepancies:
                    entity_tracker.n_in_syncs += n
                else:
                    discrepancy_details = ','.join(
                        str(d) for d in attr_discrepancies)
                    audit_report.append({
                        'discrepancy_type': 'ENTITY_MISMATCH',
                        'entity_type': entity_matcher.entity_name(),
                        'neutron_entity': n_id,
                        'vsd_entity': v.id,
                        'discrepancy_details': discrepancy_details})
                    entity_tracker.n_mismatches += n
                del neutron_ids_to_obj[n_id]
            else:
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': entity_matcher.entity_name(),
                    'neutron_entity': None,
                    'vsd_entity': v.id,
                    'discrepancy_details': 'N/A'})
                entity_tracker.v_orphans += v

        # neutron_ids_set is now unconfirmed set of neutron id's
        for (n_id, n) in six.iteritems(neutron_ids_to_obj):
            if expected_neutron_orphan and expected_neutron_orphan(n):
                entity_tracker.n_expected_orphans += n
            else:
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                    'entity_type': entity_matcher.entity_name(),
                    'neutron_entity': n_id,
                    'vsd_entity': None,
                    'discrepancy_details': 'N/A'})
                entity_tracker.n_orphans += n

        # audited entities
        entity_tracker.v_entities.report()
        # don't report excludes in non-debug; they are design internal
        entity_tracker.v_excluded_entities.report(level='DEBUG')
        # detailed reports
        entity_tracker.n_entities.report()
        entity_tracker.n_in_syncs.report()
        entity_tracker.n_mismatches.report()
        entity_tracker.n_expected_orphans.report()
        entity_tracker.n_orphans.report()
        entity_tracker.v_orphans.report()

        nbr_entities_in_sync = entity_tracker.n_in_syncs.count()

        INFO.h2('%d discrepancies reported',
                len(audit_report) - initial_audit_report_len)
        DEBUG.h2('%d entities are in sync', nbr_entities_in_sync)
        DEBUG.h2('====== audit_entities complete ======')

        return nbr_entities_in_sync

    @abc.abstractmethod
    def audit(self, audit_report):
        pass
