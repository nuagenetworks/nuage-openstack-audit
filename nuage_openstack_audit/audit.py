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

import json
import os
import six
import time

from nuage_openstack_audit.matchers.fwaas import FirewallPolicyMatcher
from nuage_openstack_audit.matchers.fwaas import FirewallRuleMatcher
from nuage_openstack_audit.utils import logger
from nuage_openstack_audit.utils.timeit import TimeIt
from nuage_openstack_audit.utils.utils import get_env_bool
from nuage_openstack_audit.utils.utils import get_env_var

LOG = logger.get_logger()

_ = logger.HeaderOne
__ = logger.HeaderTwo
___ = logger.HeaderThree


class Audit(object):

    def __init__(self, report_file=None, verbose=False, debug=False):
        initiating_time = time.strftime("%d-%m-%Y_%H:%M:%S")
        LOG.set_verbose(verbose)
        logfile = self.prep_logging(initiating_time, debug)
        LOG.user('Logfile created at %s', logfile)

        LOG.user(_('Authenticating with OpenStack'))
        self.os_client = self.create_os_client()
        self.neutron = self.os_client.neutron()

        LOG.user(_('Authenticating with Nuage VSD'))
        self.vsd = self.create_vsd_client()
        self.default_netpartition_id = self.vsd.get_netpartition_by_name(
            get_env_var('OS_DEFAULT_NETPARTITION'))['id']

        self.report_file = self.prep_report_name(report_file, initiating_time)

    @staticmethod
    def create_os_client():
        from nuage_openstack_audit.osclient.osclient import OSClient
        return OSClient()

    @staticmethod
    def create_vsd_client():
        from nuage_openstack_audit.vsdclient.vsdclient_fac import \
            VsdClientFactory
        return VsdClientFactory.new_vsd_client(
            get_env_var('OS_CMS_ID'),
            server=get_env_var('OS_VSD_SERVER'),
            base_uri=get_env_var('OS_VSD_BASE_URI', '/nuage/api/v5_0'),
            serverssl=get_env_bool('OS_VSD_SERVER_SSL', True),
            verify_cert=get_env_bool('OS_VSD_VERIFY_CERT', False),
            serverauth=get_env_var('OS_VSD_SERVER_AUTH', 'csproot:csproot'),
            auth_resource=get_env_var('OS_VSD_AUTH_RESOURCE', '/me'),
            organization=get_env_var('OS_VSD_ORGANIZATION', 'csp'),
            servertimeout=int(get_env_var('OS_VSD_SERVER_TIMEOUT', 30)),
            max_retries=int(get_env_var('OS_VSD_MAX_RETRIES', 5)))

    @staticmethod
    def expand_filename(dir_name, file_name, file_ext):
        dir_name = os.path.expanduser(dir_name)  # expand "~"
        dir_name = os.path.abspath(dir_name)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        if not file_name.endswith(file_ext):
            file_name += file_ext
        return '%s/%s_%s' % (dir_name, 'nuage_openstack_audit', file_name)

    @staticmethod
    def relative_filename(file_name):
        pwd = get_env_var('PWD', 'NOTONLINUX?')
        if file_name.startswith(pwd):
            file_name = '.' + file_name[len(pwd):]
        return file_name

    def prep_logging(self, logfile, debug):
        level = 'DEBUG' if debug else get_env_var(
            'OS_AUDIT_LOG_LEVEL', 'INFO').upper()
        logdir = get_env_var('OS_AUDIT_LOG_DIR', '.')
        logfile = self.expand_filename(logdir, logfile, '.log')
        logger.init_logging(level, logfile)
        return self.relative_filename(logfile)

    def prep_report_name(self, report_file=None, suffix='report'):
        if not report_file:
            report_dir = get_env_var(
                'OS_AUDIT_REPORT_DIR', '.')
            fixed_report_file = get_env_var(
                'OS_AUDIT_REPORT_FILE', '')
            report_file = self.expand_filename(
                report_dir, fixed_report_file or suffix, '.json')
        return report_file

    def set_report_name(self, report_file=None, suffix=None):
        self.report_file = self.prep_report_name(report_file, suffix)

    @staticmethod
    def strip_cms_id(external_id):
        return external_id.split('@')[0] if external_id else external_id

    @staticmethod
    def vsd_entity_to_neutron_id(vsd_entity):
        return Audit.strip_cms_id(vsd_entity['externalID'])

    def audit(self, neutron_list, vsd_list, entity_matcher,
              exclude_from_n_orphans=None, audit_report=None,
              provide_detailed_lists=False, quite=False):
        """audit: audit a set of neutron/vsd entities and compose a report.

        :param neutron_list: list of neutron entities under audit
        :param vsd_list: list of vsd entities under audit
        :param entity_matcher: matcher used for entity comparisons
        :param exclude_from_n_orphans: function pointer used to exclude
               entities from the neutron orphan audit. Is None, not applicable.
        :param audit_report: the audit report to append the audit results to.
               If none, a new report is started.
        :param provide_detailed_lists: Boolean flag to indicate that additional
               info must be returned apart from the audit report
        :param quite: don't report stats at INFO
        :return: audit report + additional info if requested
        """
        if not quite:
            LOG.info(___('%d neutron entities found'), len(neutron_list))
            LOG.info(___('%d vsd entities found'), len(vsd_list))

        if audit_report is None:
            audit_report = []
        n_in_syncs = set()
        v_orphans = set()
        n_mismatches = set()
        n_orphans = set()

        neutron_ids_to_obj = dict([(n['id'], n) for n in neutron_list])

        for v in vsd_list:
            n_id = self.vsd_entity_to_neutron_id(v)
            n = neutron_ids_to_obj.get(n_id)
            if n:
                attr_discrepancies = entity_matcher.compare(n, v)
                if not attr_discrepancies:
                    n_in_syncs.add(n_id)
                else:
                    discrepancy_details = ','.join(
                        str(d) for d in attr_discrepancies)
                    audit_report.append({
                        'discrepancy_type': 'ENTITY_MISMATCH',
                        'entity_type': entity_matcher.entity_name(),
                        'neutron_entity': n_id,
                        'vsd_entity': v['ID'],
                        'discrepancy_details': discrepancy_details})
                    n_mismatches.add(n_id)
                del neutron_ids_to_obj[n_id]
            else:
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': entity_matcher.entity_name(),
                    'neutron_entity': None,
                    'vsd_entity': v['ID'],
                    'discrepancy_details': 'N/A'})
                v_orphans.add(v['ID'])

        # neutron_ids_set is unconfirmed set of neutron id's now
        for n_id, n in six.iteritems(neutron_ids_to_obj):
            if not exclude_from_n_orphans or not exclude_from_n_orphans(n):
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                    'entity_type': entity_matcher.entity_name(),
                    'neutron_entity': n_id,
                    'vsd_entity': None,
                    'discrepancy_details': 'N/A'})
                n_orphans.add(n_id)

        if not quite:
            LOG.info(___('%d entities found in sync'), len(n_in_syncs))
            LOG.info(___('%d entity mismatches found'), len(n_mismatches))
            LOG.info(___('%d neutron orphans found'), len(n_orphans))
            LOG.info(___('%d vsd orphans found'), len(v_orphans))

        if provide_detailed_lists:
            return audit_report, n_in_syncs, v_orphans, n_mismatches, n_orphans
        else:
            return audit_report

    @staticmethod
    def is_fw_rule_rule_disabled(rule):
        return not rule['enabled']

    @TimeIt.timeit
    def audit_firewall_rules(self, audit_report=None):
        LOG.user(_('Auditing firewall rules'))
        return self.audit(
            self.neutron.get_firewall_rules(),
            self.vsd.get_firewall_rules(
                self.default_netpartition_id),
            FirewallRuleMatcher(),
            exclude_from_n_orphans=self.is_fw_rule_rule_disabled,
            audit_report=audit_report)

    def audit_firewall_rules_within_policy(self, policy_id,
                                           audit_report=None):
        return self.audit(
            self.neutron.get_firewall_rules_by_policy(policy_id),
            self.vsd.get_firewall_rules_by_policy(
                self.default_netpartition_id, policy_id),
            FirewallRuleMatcher(),
            exclude_from_n_orphans=self.is_fw_rule_rule_disabled,
            audit_report=audit_report,
            quite=True)

    @TimeIt.timeit
    def audit_fwaas_rules_per_policy(
            self, n_policies_in_syncs, n_policy_mismatches, n_policy_orphans,
            audit_report):
        LOG.user(_('Auditing firewall rules part of Neutron policy'))
        for policy_id in n_policies_in_syncs:
            self.audit_firewall_rules_within_policy(policy_id, audit_report)
        for policy_id in n_policy_mismatches:
            self.audit_firewall_rules_within_policy(policy_id, audit_report)
        for policy_id in n_policy_orphans:
            self.audit_firewall_rules_within_policy(policy_id, audit_report)

        return audit_report

    @TimeIt.timeit
    def audit_firewall_policies(self, audit_report=None,
                                provide_detailed_lists=False):
        LOG.user(_('Auditing firewall policies'))
        if provide_detailed_lists:
            (audit_report,
             n_in_syncs, v_orphans, n_mismatches, n_orphans) = self.audit(
                self.neutron.get_firewall_policies(),
                self.vsd.get_firewall_policies(
                    self.default_netpartition_id),
                FirewallPolicyMatcher(),
                audit_report=audit_report,
                provide_detailed_lists=provide_detailed_lists)

            return audit_report, n_in_syncs, v_orphans, n_mismatches, n_orphans
        else:
            return self.audit(
                self.neutron.get_firewall_policies(),
                self.vsd.get_firewall_policies(
                    self.default_netpartition_id),
                FirewallPolicyMatcher(),
                audit_report=audit_report)

    def audit_firewall_associations(self, n_policy_to_fw_r_sets, v_fw_info,
                                    audit_report=None):
        if audit_report is None:
            audit_report = []
        n_fw_r_in_sync = 0
        n_fw_orphans = 0
        v_fw_orphans = 0

        for v_fw in v_fw_info:
            policy_id = self.strip_cms_id(v_fw[0])
            router_id = self.strip_cms_id(v_fw[1])
            fw_r_sets = n_policy_to_fw_r_sets.get(policy_id)
            if fw_r_sets:
                router_id_associated = False
                # there can be many (FW, router) combos for same policy
                for fw_r_set in fw_r_sets:
                    if router_id in fw_r_set['router_ids']:
                        # good, remove it from this structure
                        fw_r_set['router_ids'].remove(router_id)
                        if not fw_r_set['router_ids']:
                            fw_r_sets.remove(fw_r_set)
                            if not fw_r_sets:
                                del n_policy_to_fw_r_sets[policy_id]
                        router_id_associated = True
                        n_fw_r_in_sync += 1
                        break

                if not router_id_associated:
                    # VSD ACL-router orphan :
                    # in neutron no FW is bound to this rtr
                    audit_report.append({
                        'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                        'entity_type': 'Firewall',
                        'neutron_entity': None,
                        'vsd_entity': 'ACL: %s <> Domain: %s' % (
                            v_fw[0], v_fw[1])})
                    v_fw_orphans += 1
            else:
                # VSD ALC-router orphan (OS ACL is not assoc. to any rtr)
                audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': 'Firewall',
                    'neutron_entity': None,
                    'vsd_entity': 'ACL: %s <> Domain: %s' % (
                        v_fw[0], v_fw[1])})
                v_fw_orphans += 1

        # now check the neutron orphans
        for fw_r_sets in six.itervalues(n_policy_to_fw_r_sets):
            for fw_r_set in fw_r_sets:
                for r_id in fw_r_set['router_ids']:
                    audit_report.append({
                        'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                        'entity_type': 'Firewall',
                        'neutron_entity': 'Firewall: %s <> Router: %s' % (
                            fw_r_set['firewall_id'], r_id),
                        'vsd_entity': None})
                    n_fw_orphans += 1

        LOG.info(__('%d entities found in sync'), n_fw_r_in_sync)
        LOG.info(__('%d neutron orphans found'), n_fw_orphans)
        LOG.info(__('%d vsd orphans found'), v_fw_orphans)

        return audit_report

    @TimeIt.timeit
    def audit_firewalls(self, audit_report=None):
        LOG.user(_('Auditing firewalls'))
        n_fws = self.neutron.get_firewalls()
        v_fw_info = self.vsd.get_firewalls(self.default_netpartition_id)
        n_policy_to_fw_r_sets = {}
        n_fw_r_associations = 0

        for n_fw in n_fws:
            p = n_policy_to_fw_r_sets.get(n_fw['firewall_policy_id'])
            if p is None:
                p = n_policy_to_fw_r_sets[n_fw['firewall_policy_id']] = []
            p.append({'firewall_id': n_fw['id'],
                      'router_ids': set(n_fw['router_ids'])})
            n_fw_r_associations += len(n_fw['router_ids'])

        LOG.info(___('%d neutron entities found'), n_fw_r_associations)
        LOG.info(___('%d vsd associations found'), len(v_fw_info))

        return self.audit_firewall_associations(
            n_policy_to_fw_r_sets, v_fw_info, audit_report)

    def end_report(self, audit_report):
        LOG.user(_('Reporting %d discrepancies'), len(audit_report))
        with open(self.report_file, 'w') as outfile:
            json.dump(audit_report, outfile, indent=4)
        LOG.user('Audit report written to %s',
                 self.relative_filename(self.report_file))

    def audit_fwaas_resources_per_policy(self):
        audit_report, n_in_syncs, v_orphans, n_mismatches, n_orphans = \
            self.audit_firewall_policies(provide_detailed_lists=True)
        self.audit_fwaas_rules_per_policy(n_in_syncs, n_mismatches, n_orphans,
                                          audit_report)
        self.audit_firewalls(audit_report)
        self.end_report(audit_report)

        return audit_report

    def audit_fwaas_resources(self):
        audit_report = []
        self.audit_firewall_rules(audit_report)
        self.audit_firewall_policies(audit_report)
        self.audit_firewalls(audit_report)
        self.end_report(audit_report)

        return audit_report

    def do_audit(self, _=None):
        start_time = time.time()
        audit_report = self.audit_fwaas_resources()
        elapse_time = int(time.time() - start_time)
        LOG.info('Audit complete in %d secs', elapse_time)

        return audit_report
