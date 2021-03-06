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

import six

from nuage_openstack_audit.utils.entity_tracker import tracked
from nuage_openstack_audit.utils.logger import Reporter

INFO = Reporter('INFO')
DEBUG = Reporter('DEBUG')


class Audit(object):

    def __init__(self, cms_id, ignore_vsd_orphans=False):
        self.vspk_filter = "externalID ENDSWITH '@{}'".format(cms_id)
        self.ignore_vsd_orphans = ignore_vsd_orphans

    @staticmethod
    def strip_cms_id(external_id):
        return external_id.split('@')[0] if external_id else external_id

    # ---

    @staticmethod
    def vsd_entity_to_neutron_id(vsd_entity):
        return Audit.strip_cms_id(vsd_entity.external_id)

    @staticmethod
    def _default_get_ext_id(neutron_entity):
        return neutron_entity['id']

    def audit_entities(self, audit_report,
                       neutron_entities,
                       vsd_entities,
                       entity_matcher,
                       external_id_getter=None,
                       excluded_vsd_entity=None,
                       expected_neutron_orphan=None,
                       neutron_id_to_vsd_ids_dict=None,
                       on_in_sync=None,
                       report_tracked_entities=True):
        """Audit a set of neutron/vsd entities.

        :param audit_report: the audit report to report to
        :param neutron_entities: iterable of neutron entities under audit
        :param vsd_entities: iterable of vsd entities under audit
        :param entity_matcher: matcher used for entity comparisons
        :param excluded_vsd_entity: function used to exclude entities from
               the VSD audit. If None, not applicable.
        :param expected_neutron_orphan: function used to exclude entities from
               the neutron orphan audit. If None, not applicable.
        :param external_id_getter: Function that takes a neutron_entity and
                                   returns the external id (without CMS ID).
        :param neutron_id_to_vsd_ids_dict: if passed, this dict is filled with
               neutron id to vsd id mappings
        :param on_in_sync: function used to verify resource further upon
                           being in sync, going further than the matcher.
                           Called as on_sync(vspk_object, neutron_object)
        :param report_tracked_entities: Whether output the tracked entity
                                        counters
        :return number entities in sync
        """
        DEBUG.h2('====== audit_entities (%s) ======',
                 entity_matcher.__class__.__name__)

        initial_audit_report_len = len(audit_report)

        n_entities = tracked('neutron entities', neutron_entities)
        v_entities = tracked('vsd entities')
        v_excluded_entities = tracked('vsd excluded entities')
        n_in_syncs = tracked('neutron/vsd in syncs entities')
        n_mismatches = tracked('neutron mismatch entities')
        n_expected_orphans = tracked('neutron orphan-by-design entities')
        n_orphans = tracked('neutron orphan entities')
        v_orphans = tracked('vsd orphan entities')

        if not external_id_getter:
            external_id_getter = self._default_get_ext_id

        neutron_ids_to_obj = {
            external_id_getter(neutron_entity): neutron_entity
            for neutron_entity in neutron_entities}

        for vsd_entity in vsd_entities:

            if excluded_vsd_entity and excluded_vsd_entity(vsd_entity):
                v_excluded_entities += vsd_entity
                continue

            v_entities += vsd_entity
            neutron_id = self.vsd_entity_to_neutron_id(vsd_entity)

            neutron_entity = neutron_ids_to_obj.get(neutron_id)
            if neutron_entity:
                if neutron_id_to_vsd_ids_dict is not None:
                    neutron_id_to_vsd_ids_dict[neutron_id] = vsd_entity.id

                attr_discrepancies = list(
                    entity_matcher.compare(neutron_entity, vsd_entity))
                if not attr_discrepancies:
                    n_in_syncs += neutron_entity
                    if on_in_sync:
                        on_in_sync(vsd_entity, neutron_entity)
                else:
                    discrepancy_details = ','.join(
                        str(d) for d in attr_discrepancies)
                    audit_report.append({
                        'discrepancy_type': 'ENTITY_MISMATCH',
                        'entity_type': entity_matcher.entity_name(),
                        'neutron_entity': neutron_id,
                        'vsd_entity': vsd_entity.id,
                        'discrepancy_details': discrepancy_details})
                    n_mismatches += neutron_entity
                del neutron_ids_to_obj[neutron_id]
            else:
                if not self.ignore_vsd_orphans:
                    # VSD orphans can only be audited when there is no project
                    # isolation.
                    audit_report.append({
                        'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                        'entity_type': entity_matcher.entity_name(),
                        'neutron_entity': None,
                        'vsd_entity': vsd_entity.id,
                        'discrepancy_details': 'N/A'})
                    v_orphans += vsd_entity

        # neutron_ids_set is now unconfirmed set of neutron id's
        for (neutron_id, neutron_entity) in six.iteritems(neutron_ids_to_obj):
            if (expected_neutron_orphan and
                    expected_neutron_orphan(neutron_entity)):
                n_expected_orphans += neutron_entity
            else:
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                    'entity_type': entity_matcher.entity_name(),
                    'neutron_entity': neutron_id,
                    'vsd_entity': None,
                    'discrepancy_details': 'N/A'})
                n_orphans += neutron_entity

        nbr_entities_in_sync = n_in_syncs.count()

        if report_tracked_entities:
            # audited entities
            v_entities.report()
            # don't report excludes in non-debug; they are design internal
            v_excluded_entities.report(level='DEBUG')
            # detailed reports
            n_entities.report()
            n_in_syncs.report()
            n_mismatches.report()
            n_expected_orphans.report()
            n_orphans.report()
            v_orphans.report()

            INFO.h2('%d discrepancies reported',
                    len(audit_report) - initial_audit_report_len)
            DEBUG.h2('%d entities are in sync', nbr_entities_in_sync)
            DEBUG.h2('====== audit_entities (%s) complete ======',
                     entity_matcher.__class__.__name__)

        return nbr_entities_in_sync

    @abc.abstractmethod
    def audit(self, *args, **kwargs):
        pass
