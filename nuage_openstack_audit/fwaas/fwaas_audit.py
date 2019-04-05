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

INFO = Reporter('INFO')
DEBUG = Reporter('DEBUG')


class FWaaSAudit(Audit):

    inactive_firewall_ids = None  # fw ids of admin down firewalls
    active_policy_ids = None  # policies that do have admin down firewalls
    faked_n_policies_for_admin_down_fws = None  # faked neutron policies
    n_rule_ids_to_vsd = None  # mapping neutron rule ids to vsd rule ids

    def __init__(self, neutron, vsd, cms_id, ignore_vsd_orphans=False):
        super(FWaaSAudit, self).__init__(cms_id, ignore_vsd_orphans)

        self.neutron = neutron
        self.vsd = vsd

        # initialize, so repeated unit tests don't suffer from leftovers
        FWaaSAudit.inactive_firewall_ids = set()
        FWaaSAudit.active_policy_ids = set()
        FWaaSAudit.faked_n_policies_for_admin_down_fws = []
        FWaaSAudit.n_rule_ids_to_vsd = {}

    @TimeIt.timeit
    def audit_firewalls(self, audit_report):
        INFO.h1('Auditing firewalls')

        ''' n_policy_to_fw_r_sets

            List of dicts mapping
            neutron FW policy id to (FW id, FW state, list of router ids) tuple

            BUT, for admin down FW's, we fake a new policy id ourselves

            In this algorithm, remember:
            (FW, router) <-> (FW policy) relationship is (many) <-> (1)

        '''
        n_fws = self.neutron.get_firewalls()
        n_policy_to_fw_r_sets = {}

        for n_fw in n_fws:
            if n_fw['admin_state_up']:
                policy_id = n_fw['firewall_policy_id']
                self.active_policy_ids.add(policy_id)

            else:
                self.inactive_firewall_ids.add(n_fw['id'])

                # for admin down policy, we fake a policy to exist whose id
                # is linked to the firewall id
                self.faked_n_policies_for_admin_down_fws.append(
                    {
                        'id': n_fw['id'],
                        'name': 'DROP_ALL_ACL_' + n_fw['id'],
                        'description': 'Drop all acl for firewall %s when '
                                       'admin_state_up=False' % n_fw['id'],
                        'firewall_rules': []
                    })
                policy_id = n_fw['id']

            p = n_policy_to_fw_r_sets.get(policy_id)
            if p is None:
                p = n_policy_to_fw_r_sets[policy_id] = []
            p.append(
                {
                    'firewall_id': n_fw['id'],
                    'firewall_admin_up': n_fw['admin_state_up'],
                    'router_ids': set(n_fw['router_ids'])
                })

        return self.audit_firewall_associations(
            audit_report,
            n_fws,
            n_policy_to_fw_r_sets,
            self.vsd.get_firewalls())

    def audit_firewall_associations(
            self, audit_report,
            n_firewalls,  # for tracking only
            n_policy_to_fw_r_sets,
            v_fw_associated_ext_ids):
        """Audit firewalls with acl-domain associations.

        :param audit_report: the audit report to report to
        :param n_firewalls: iterable of neutron firewalls, only used for
               reporting purpose
        :param n_policy_to_fw_r_sets: a set of neutron FW ACL policy to
               list of tuples of neutron firewall id and set of router ids
        :param v_fw_associated_ext_ids: iterable over (VSD FW ACLs ext ID +
               VSD domain ext ID) tuples
        """
        n_entities = tracked('neutron entities', n_firewalls)
        v_entities = tracked('vsd entities')
        n_in_syncs = tracked('neutron/vsd in syncs entities')
        n_orphans = tracked('neutron orphan entities')
        v_orphans = tracked('vsd orphan entities')

        ''' __the algorithm__

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
                 VSD (ACL, domain) combo.
        '''
        initial_audit_report_len = len(audit_report)

        for v_fw in v_fw_associated_ext_ids:
            v_acl_id = v_fw.acl_id
            v_acl_external_id = v_fw.acl_external_id
            v_domain_id = v_fw.domain_id
            v_domain_external_id = v_fw.domain_external_id

            v_entities += (v_acl_id, v_acl_external_id,
                           v_domain_id, v_domain_external_id)

            policy_id = self.strip_cms_id(v_acl_external_id)
            router_id = self.strip_cms_id(v_domain_external_id)

            fw_r_sets = n_policy_to_fw_r_sets.get(policy_id) or []
            router_id_associated = False

            for fw_r_set in fw_r_sets:
                if router_id in fw_r_set['router_ids']:

                    # match; remove it from this structure
                    fw_r_set['router_ids'].remove(router_id)
                    if not fw_r_set['router_ids']:
                        fw_r_sets.remove(fw_r_set)
                        if not fw_r_sets:
                            del n_policy_to_fw_r_sets[policy_id]
                    router_id_associated = True
                    n_in_syncs += fw_r_set['firewall_id']
                    break

            if not router_id_associated:
                # VSD ACL-router orphan :
                # in neutron no FW is bound to this rtr with that policy
                # VSD orphans can only be audited when there is no project
                # isolation.
                if not self.ignore_vsd_orphans:
                    audit_report.append({
                        'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                        'entity_type': 'Firewall',
                        'neutron_entity': None,
                        'vsd_entity': 'ACL: %s <> Domain: %s' % (
                            v_acl_id, v_domain_id),
                        'discrepancy_details': 'N/A'})
                    v_orphans += v_acl_id

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
                    n_orphans += fw_r_set['firewall_id']

        v_entities.report()
        n_entities.report()
        n_in_syncs.report()
        n_orphans.report()
        v_orphans.report()

        INFO.h2('%d discrepancies reported',
                len(audit_report) - initial_audit_report_len)

        return n_in_syncs.count()

    @staticmethod
    def is_inactive_v_fw_acl(acl):
        return (Audit.strip_cms_id(acl.external_id)
                in FWaaSAudit.inactive_firewall_ids)

    @staticmethod
    def is_inactive_n_fw_policy(policy):
        return policy['id'] not in FWaaSAudit.active_policy_ids

    @staticmethod
    def neutron_fw_rule_ids_to_vsd_rule_ids(n_rule_ids):
        assert FWaaSAudit.n_rule_ids_to_vsd
        vsd_rule_ids = []
        for rule_id in n_rule_ids:
            vsd_rule_id = FWaaSAudit.n_rule_ids_to_vsd.get(rule_id)
            if vsd_rule_id is not None:
                vsd_rule_ids.append(vsd_rule_id)
        return vsd_rule_ids

    @TimeIt.timeit
    def audit_firewall_policies(self, audit_report):
        INFO.h1('Auditing firewall policies')

        n_fw_policies = self.neutron.get_firewall_policies()

        # add faked policies for inactive firewalls
        n_fw_policies.extend(self.faked_n_policies_for_admin_down_fws)

        in_syncs = self.audit_entities(
            audit_report,
            n_fw_policies,
            self.vsd.get_firewall_acls(vspk_filter=self.vspk_filter),
            FirewallPolicyMatcher(self.neutron_fw_rule_ids_to_vsd_rule_ids),
            expected_neutron_orphan=self.is_inactive_n_fw_policy)

        return in_syncs

    @staticmethod
    def is_fw_rule_rule_disabled(rule):
        return not rule['enabled']

    @TimeIt.timeit
    def audit_firewall_rules(self, audit_report):
        INFO.h1('Auditing firewall rules')

        in_syncs = self.audit_entities(
            audit_report,
            self.neutron.get_firewall_rules(),
            self.vsd.get_firewall_rules(vspk_filter=self.vspk_filter),
            FirewallRuleMatcher(),
            expected_neutron_orphan=self.is_fw_rule_rule_disabled,
            neutron_id_to_vsd_ids_dict=FWaaSAudit.n_rule_ids_to_vsd)

        return in_syncs

    def audit(self):
        audit_report = []
        nbr_entities_in_sync = 0

        nbr_entities_in_sync += self.audit_firewalls(audit_report)
        nbr_entities_in_sync += self.audit_firewall_rules(audit_report)
        nbr_entities_in_sync += self.audit_firewall_policies(audit_report)

        return audit_report, nbr_entities_in_sync
