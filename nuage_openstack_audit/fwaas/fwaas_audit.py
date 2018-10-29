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

import six

from nuage_openstack_audit.audit import Audit
from nuage_openstack_audit.fwaas.fwaas_matchers import FirewallPolicyMatcher
from nuage_openstack_audit.fwaas.fwaas_matchers import FirewallRuleMatcher
from nuage_openstack_audit.utils.entity_tracker import tracked
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.timeit import TimeIt

INFO = Reporter()


class FWaaSAudit(Audit):

    inactive_firewall_ids = set()  # firewalls that are ADMIN DOWN
    active_policy_ids = None  # policies that do have ADMIN UP firewalls
    n_rule_ids_to_vsd = None  # mapping neutron rule ids to vsd rule ids

    def __init__(self, neutron, vsd):
        self.neutron = neutron
        self.vsd = vsd

    @TimeIt.timeit
    def audit_firewalls(self, audit_report):
        INFO.h1('Auditing firewalls')

        ''' __n_policy_to_fw_r_sets__

            Building a list of dicts mapping neutron FW policy ID to tuple of
                (FW id, list of router ids)

            Remember: (FW, router)<->(FW policy) relationship is (many)<->(1)
        '''
        n_policy_to_fw_r_sets = {}

        n_fws = self.neutron.get_firewalls()

        for n_fw in n_fws:
            if n_fw['admin_state_up']:
                p = n_policy_to_fw_r_sets.get(n_fw['firewall_policy_id'])
                if p is None:
                    p = n_policy_to_fw_r_sets[n_fw['firewall_policy_id']] = []
                p.append({'firewall_id': n_fw['id'],
                          'router_ids': set(n_fw['router_ids'])})
            else:
                FWaaSAudit.inactive_firewall_ids.add(n_fw['id'])

        FWaaSAudit.active_policy_ids = set(n_policy_to_fw_r_sets.keys())

        self.audit_firewall_associations(
            audit_report,
            n_fws,
            n_policy_to_fw_r_sets,
            self.vsd.get_firewalls(),
            excluded_vsd_policy_list=self.inactive_firewall_ids)

    @staticmethod
    def is_vsd_drop_acl_of_inactive_fw(policy):
        return (Audit.strip_cms_id(policy.external_id)
                in FWaaSAudit.inactive_firewall_ids)

    @staticmethod
    def is_inactive_fw_policy(policy):
        return policy['id'] not in FWaaSAudit.active_policy_ids

    @staticmethod
    def neutron_fw_rule_ids_to_vsd_rule_ids(n_rule_ids):
        assert FWaaSAudit.n_rule_ids_to_vsd
        vsd_rule_ids = []
        for rule_id in n_rule_ids:
            vsd_rule_id = FWaaSAudit.n_rule_ids_to_vsd[rule_id]
            if vsd_rule_id is not None:
                vsd_rule_ids.append(vsd_rule_id)
        return vsd_rule_ids

    @TimeIt.timeit
    def audit_firewall_policies(self, audit_report):
        INFO.h1('Auditing firewall policies')
        self.audit_entities(
            audit_report,
            self.neutron.get_firewall_policies(),
            self.vsd.get_firewall_acls(),
            FirewallPolicyMatcher(self.neutron_fw_rule_ids_to_vsd_rule_ids),
            excluded_vsd_entity=self.is_vsd_drop_acl_of_inactive_fw,
            expected_neutron_orphan=self.is_inactive_fw_policy)

    def audit_firewall_associations(
            self, audit_report,
            n_firewalls,
            n_policy_to_fw_r_sets,
            v_fw_associated_ext_ids,
            excluded_vsd_policy_list=None):
        """Audits firewalls with acl-domain associations.

        :param audit_report: the audit report to report to
        :param n_firewalls: iterable of neutron firewalls, only used for
               reporting purpose
        :param n_policy_to_fw_r_sets: a set of neutron FW ACL policy to
               list of tuples of neutron firewall id and set of router ids
        :param v_fw_associated_ext_ids: iterable over (VSD FW ACLs ext ID +
               VSD domain ext ID) tuples
        :param excluded_vsd_policy_list: list of excluded VSD FW ACL ext IDs
        """
        v_entities = tracked('vsd entities')
        n_entities = tracked('neutron entities', n_firewalls)
        n_fw_r_in_sync = tracked('neutron in sync entities')
        n_fw_orphans = tracked('neutron orphan entities')
        v_fw_orphans = tracked('vsd orphan entities')

        ''' __the algorithm__
                                          ~
            Remember: (FW, router)<->(FW policy) relationship is (many)<->(1)
                                          ~
            1. Loop over VSD (ACL, domain) tuples using vspk iterator
            1.1. Fetch the list of neutron (FW, set of routers) tuples for the
                 VSD ACL corresponding neutron FW policy
            1.1.1. If there is such list, loop over it
            1.1.1.1. _If_ the 1.-domain external ID matches one of the
                     routers in this tuple, we have a match;
                     remove the router from the routers of this tuple;
                     if this was the last router, remove the entire tuple;
                     if this was the last tuple, remove the neutron FW policy
                     from the 1.1 list altogether.
            1.1.2. If no match was found, we have a VSD (ACL, domain) orphan,
                   i.e. which doesn't match any router in neutron, i.e. no FW
                   is bound to this router with that policy.
            1.2. All remaining entities obtained from 1.1 are neutron orphans,
                 i.e. Firewalls in neutron which don't have a corresponding
                 VSD (ACL, domain) combo. Unless, this was a VSD excluded ACL.
        '''
        initial_audit_report_len = len(audit_report)

        for v_fw in v_fw_associated_ext_ids:
            v_entities += (v_fw[0], v_fw[1])
            policy_id = self.strip_cms_id(v_fw[0])
            router_id = self.strip_cms_id(v_fw[1])
            fw_r_sets = n_policy_to_fw_r_sets.get(policy_id)
            router_id_associated = False
            if fw_r_sets:
                # there can be many (FW, router) combos for same policy
                for fw_r_set in fw_r_sets:
                    if router_id in fw_r_set['router_ids']:
                        # match; remove it from this structure
                        fw_r_set['router_ids'].remove(router_id)
                        if not fw_r_set['router_ids']:
                            fw_r_sets.remove(fw_r_set)
                            if not fw_r_sets:
                                del n_policy_to_fw_r_sets[policy_id]
                        router_id_associated = True
                        n_fw_r_in_sync += fw_r_set['firewall_id']
                        break

            if (not router_id_associated and
                    (not excluded_vsd_policy_list or
                     self.strip_cms_id(v_fw[0]) not in
                     excluded_vsd_policy_list)):
                # VSD ACL-router orphan :
                # in neutron no FW is bound to this rtr with that policy
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': 'Firewall',
                    'neutron_entity': None,
                    'vsd_entity': 'ACL: %s <> Domain: %s' % (
                        v_fw[0], v_fw[1]),
                    'discrepancy_details': 'N/A'})
                v_fw_orphans += v_fw[0]

        # now check the neutron orphans
        for fw_r_sets in six.itervalues(n_policy_to_fw_r_sets):
            for fw_r_set in fw_r_sets:
                for r_id in fw_r_set['router_ids']:
                    audit_report.append({
                        'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                        'entity_type': 'Firewall',
                        'neutron_entity': 'Firewall: %s <> Router: %s' % (
                            fw_r_set['firewall_id'], r_id),
                        'vsd_entity': None,
                        'discrepancy_details': 'N/A'})
                    n_fw_orphans += fw_r_set['firewall_id']

        v_entities.report()
        n_entities.report()
        n_fw_r_in_sync.report()
        n_fw_orphans.report()
        v_fw_orphans.report()

        INFO.h2('%d discrepancies reported',
                len(audit_report) - initial_audit_report_len)

    @staticmethod
    def is_fw_rule_rule_disabled(rule):
        return not rule['enabled']

    @TimeIt.timeit
    def audit_firewall_rules(self, audit_report):
        INFO.h1('Auditing firewall rules')

        FWaaSAudit.n_rule_ids_to_vsd = self.audit_entities(
            audit_report,
            self.neutron.get_firewall_rules(),
            self.vsd.get_firewall_rules(),
            FirewallRuleMatcher(),
            expected_neutron_orphan=self.is_fw_rule_rule_disabled)

    def audit(self, audit_report):
        self.audit_firewalls(audit_report)
        self.audit_firewall_rules(audit_report)
        self.audit_firewall_policies(audit_report)
