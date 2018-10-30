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

import functools
import mock
import testtools
import time

from nuage_openstack_audit.main import Main
from nuage_openstack_audit.osclient.osclient import Neutron
from nuage_openstack_audit.osclient.osclient import OSClient
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.utils import Utils
from nuage_openstack_audit.vsdclient.vsdclient import VsdClient

# run me using:
# python -m testtools.run nuage_openstack_audit/test/fwaas_audit_test.py

# *****************************************************************************
#  CAUTION : THIS IS NOT A REAL UNIT TEST ; IT REQUIRES A FULL OS-VSD SETUP,
#            SETUP WITH AUDIT ENV VARIABLES CORRECTLY SET.
# *****************************************************************************

WARN = Reporter('WARN')


def header():
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            if f.func_code.co_name != 'wrapper':
                # make sure there is at least 1 sec in between tests such that
                # report file is different
                time.sleep(1)
                print("\n=== START of {} ===".format(f.func_code.co_name))
            start_time = time.time()
            result = f(self, *func_args, **func_kwargs)
            exec_time = int(time.time() - start_time)
            if f.func_code.co_name != 'wrapper':
                print("=== Execution time = {} SECS ===".format(exec_time))
                print("=== END of {} ===".format(f.func_code.co_name))
            return result
        return wrapper
    return decorator


class FWaaSAuditTestMixin(object):

    main = None
    routers = []
    fws = []
    fw_policies = []
    fw_rules = []
    nr_firewalls = 0
    nr_rules_per_fw = 0
    neutron = None

    @classmethod
    def _setup_cls(cls, alternate_firewall_admin_state=False):

        verbose = Utils.get_env_bool('OS_AUDIT_VERBOSE')
        extreme_verbose = Utils.get_env_bool('OS_AUDIT_EXTREME_VERBOSE')
        log_level = Utils.get_env_var('OS_AUDIT_LOG_LEVEL', 'INFO')

        WARN.h0('VERBOSE is %s, set OS_AUDIT_VERBOSE to change', verbose)
        if verbose or extreme_verbose:
            WARN.h0('Extreme VERBOSE is %s, set OS_AUDIT_EXTREME_VERBOSE '
                    'to change', extreme_verbose)
        WARN.h0('DEBUG is %s, set OS_AUDIT_LOG_LEVEL to change',
                'debug' in log_level.lower())

        cls.main = Main(Utils.TestMainArgs('fwaas',
                                           verbose=verbose,
                                           extreme_verbose=extreme_verbose))
        cls.routers = []
        cls.fws = []
        cls.fw_policies = []
        cls.fw_rules = []

        cls.nr_firewalls = int(
            Utils.get_env_var('OS_AUDIT_TEST_NR_FIREWALLS', 3))
        cls.nr_firewall_policies = cls.nr_firewalls
        cls.nr_rules_per_fw = cls.nr_firewalls - 1  # 1 rule is added on top

        cls.neutron = OSClient().neutron()  # for building up test resources

        print('\n===== Start of tests =====')
        if not Utils.get_env_bool('OS_AUDIT_TEST_SKIP_SETUP'):
            print('\n=== Creating %d firewalls ===' % cls.nr_firewalls)
            admin_state_up = True
            for f in range(cls.nr_firewalls):
                fw_policy_rule_ids = []
                print('Creating %d+1 rules for fw %s (admin %s)' % (
                    cls.nr_rules_per_fw, f,
                    'up' if admin_state_up else 'down'))
                for r in range(cls.nr_rules_per_fw):
                    rule = cls.neutron.create_firewall_rule()
                    cls.fw_rules.append(rule)
                    fw_policy_rule_ids.append(rule['id'])
                # + add 1 disabled rule also
                rule = cls.neutron.create_firewall_rule(enabled=False)
                cls.fw_rules.append(rule)
                fw_policy_rule_ids.append(rule['id'])
                # create policy out of the rules
                policy = cls.neutron.create_firewall_policy(
                    'policy', fw_policy_rule_ids)
                cls.fw_policies.append(policy)
                router = cls.neutron.create_router('router')
                cls.routers.append(router)
                cls.fws.append(cls.neutron.create_firewall(
                    policy, router, admin_state_up))
                if alternate_firewall_admin_state:
                    admin_state_up = not admin_state_up  # alternate

    @classmethod
    def _teardown_cls(cls):
        print('\n===== End of tests =====')
        if not Utils.get_env_bool('OS_AUDIT_TEST_SKIP_TEARDOWN'):
            print('\n=== Deleting %d firewalls ===' % len(cls.fws))
            for fw in cls.fws:
                cls.neutron.delete_firewall(fw)
            print('=== Deleting %d policies ===' % len(cls.fw_policies))
            for fw_policy in cls.fw_policies:
                cls.neutron.delete_firewall_policy(fw_policy)
            print('=== Deleting %d rules ===' % len(cls.fw_rules))
            for fw_rule in cls.fw_rules:
                cls.neutron.delete_firewall_rule(fw_rule)
            print('=== Deleting %d routers ===' % len(cls.routers))
            for router in cls.routers:
                cls.neutron.delete_router(router)


class FWaaSAuditTest(testtools.TestCase, FWaaSAuditTestMixin):

    @classmethod
    def setUpClass(cls):
        cls._setup_cls()

    @classmethod
    def tearDownClass(cls):
        cls._teardown_cls()

    @header()
    def test_firewall_audit(self):
        audit_report = self.main.run()

        # expecting zero discrepancies
        self.assertEqual(0, len(audit_report))

    @mock.patch.object(VsdClient, 'get_firewalls',
                       return_value=[])
    @mock.patch.object(VsdClient, 'get_firewall_acls',
                       return_value=[])
    @mock.patch.object(VsdClient, 'get_firewall_rules',
                       return_value=[])
    @header()
    def test_firewall_audit_mocked_empty_vsd(self, *_):
        audit_report = self.main.run()

        expected_fw_r_d = self.nr_firewalls
        expected_acl_d = self.nr_firewalls
        expected_rules_d = self.nr_firewalls * self.nr_rules_per_fw
        self.assertEqual(
            expected_fw_r_d + expected_acl_d + expected_rules_d,
            len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("ORPHAN_NEUTRON_ENTITY",
                             discrepancy["discrepancy_type"])

    @mock.patch.object(Neutron, 'get_firewalls',
                       return_value=[])
    @mock.patch.object(Neutron, 'get_firewall_policies',
                       return_value=[])
    @mock.patch.object(Neutron, 'get_firewall_rules',
                       return_value=[])
    @header()
    def test_firewall_audit_mocked_empty_neutron(self, *_):
        audit_report = self.main.run()

        expected_fw_r_d = self.nr_firewalls
        expected_acl_d = self.nr_firewalls
        expected_rules_d = self.nr_firewalls * self.nr_rules_per_fw
        self.assertEqual(
            expected_fw_r_d + expected_acl_d + expected_rules_d,
            len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("ORPHAN_VSD_ENTITY",
                             discrepancy["discrepancy_type"])

    def get_firewall_rules_with_action_deny(self, policy_id=None):
        # -- near-equal original method --
        if policy_id:
            rules = self.client.list_firewall_rules(
                firewall_policy_id=policy_id)['firewall_rules']
        else:
            rules = self.client.list_firewall_rules()['firewall_rules']
        # -- near-equal original method --

        for r in rules:
            r['action'] = 'deny'
        return rules

    @mock.patch.object(Neutron, 'get_firewall_rules',
                       get_firewall_rules_with_action_deny)
    @header()
    def test_firewall_audit_with_rules_having_action_mismatch(self):
        audit_report = self.main.run()

        expected_rules_d = self.nr_firewalls * self.nr_rules_per_fw
        self.assertEqual(expected_rules_d, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("ENTITY_MISMATCH",
                             discrepancy["discrepancy_type"])
            self.assertEqual("Firewall rule", discrepancy["entity_type"])
            self.assertEqual("('stateful', 'False != True'),"
                             "('action', 'DROP != FORWARD')",
                             discrepancy['discrepancy_details'])

    def get_firewall_policies_with_reversed_rules(self):
        policies = self.client.list_firewall_policies()['firewall_policies']
        for policy in policies:
            policy['firewall_rules'] = reversed(policy['firewall_rules'])
        return policies

    @mock.patch.object(Neutron, 'get_firewall_policies',
                       get_firewall_policies_with_reversed_rules)
    @header()
    def test_firewall_audit_with_reversed_rule_order_inside_policy(self):
        audit_report = self.main.run()

        expected_rules_d = self.nr_firewall_policies
        self.assertEqual(expected_rules_d, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("ENTITY_MISMATCH",
                             discrepancy["discrepancy_type"])
            self.assertEqual("Firewall policy", discrepancy["entity_type"])
            self.assertIn('rule_ids', discrepancy["discrepancy_details"])


class FWaaSAuditTestAlternatingFirewallStates(
        testtools.TestCase, FWaaSAuditTestMixin):

    @classmethod
    def setUpClass(cls):
        cls._setup_cls(alternate_firewall_admin_state=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown_cls()

    @header()
    def test_firewall_audit(self):
        audit_report = self.main.run()

        # expecting zero discrepancies
        self.assertEqual(0, len(audit_report))
