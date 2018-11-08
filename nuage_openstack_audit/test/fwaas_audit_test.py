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
import six
import testtools
import time

# system under test
from nuage_openstack_audit.main import Main  # under test
from nuage_openstack_audit.osclient.osclient import Neutron  # for mocking
from nuage_openstack_audit.vsdclient.vsdclient import VsdClient  # for mocking

# test code
from nuage_openstack_audit.osclient.osclient import OSCredentials  # reused
from nuage_openstack_audit.osclient.osclient import Keystone  # reused
from nuage_openstack_audit.test.neutron_test_helper import NeutronTestHelper
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.utils import Utils

# run me using:
# python -m testtools.run nuage_openstack_audit/test/fwaas_audit_test.py

# *****************************************************************************
#  CAUTION : THIS IS NOT A REAL UNIT TEST ; IT REQUIRES A FULL OS-VSD SETUP,
#            SETUP WITH AUDIT ENV VARIABLES CORRECTLY SET.
# *****************************************************************************

USER = Reporter('USER')

developer_modus = Utils.get_env_bool('OS_AUDIT_DEVELOPER_MODUS')
verbose = Utils.get_env_bool('OS_AUDIT_VERBOSE')
extreme_verbose = Utils.get_env_bool('OS_AUDIT_EXTREME_VERBOSE')
log_level = Utils.get_env_var('OS_AUDIT_LOG_LEVEL', 'INFO')

# -----------------------------------------------------------------------------
USER.set_color(USER.BLUE)
if developer_modus:
    USER.report('Developer modus is on, which implies debug & extreme verbose')
else:
    USER.report('VERBOSE is %s, set OS_AUDIT_VERBOSE to change', verbose)
    if verbose or extreme_verbose:
        USER.report('Extreme VERBOSE is %s, set OS_AUDIT_EXTREME_VERBOSE '
                    'to change', extreme_verbose)
    USER.report('DEBUG is %s, set OS_AUDIT_LOG_LEVEL to change',
                'debug' in log_level.lower())
USER.set_color(USER.ENDC).newline()
# -----------------------------------------------------------------------------


def header():
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            if six.get_function_code(f).co_name != 'wrapper':
                # make sure there is at least 1 sec in between tests such that
                # report file is different
                time.sleep(1)
                print("\n=== START of {} ===".format(
                    six.get_function_code(f).co_name))
            start_time = time.time()
            result = f(self, *func_args, **func_kwargs)
            exec_time = int(time.time() - start_time)
            if six.get_function_code(f).co_name != 'wrapper':
                print("=== Execution time = {} SECS ===".format(exec_time))
                print("=== END of {} ===".format(
                    six.get_function_code(f).co_name))
            return result
        return wrapper
    return decorator


def get_nbr_firewalls_under_test():
    return int(Utils.get_env_var('OS_AUDIT_TEST_NR_FIREWALLS', 3))


class FirewallAuditBase(testtools.TestCase):

    neutron = None
    main = None

    routers = None
    fws = None
    fw_policies = None
    fw_rules = None

    nbr_firewalls = 0
    nbr_firewalls_up = 0
    nbr_firewalls_down = 0
    nbr_firewall_policies = 0
    nbr_enabled_rules_per_fw = 0
    nbr_disabled_rules_per_fw = 0
    nbr_rules_per_fw = 0
    nbr_enabled_fw_rules = 0
    nbr_fw_rules = 0

    @classmethod
    def setUpClass(cls):
        if not cls.nbr_firewalls:
            return  # done

        cls.routers = []
        cls.fws = []
        cls.fw_policies = []
        cls.fw_rules = []

        cls.nbr_firewalls_up = 0  # incremented below, but important to reset
        cls.nbr_firewalls_down = 0  # incremented below
        cls.nbr_firewall_policies = cls.nbr_firewalls
        cls.nbr_enabled_rules_per_fw = cls.nbr_firewalls - 1
        cls.nbr_disabled_rules_per_fw = 1
        cls.nbr_rules_per_fw = (cls.nbr_enabled_rules_per_fw +
                                cls.nbr_disabled_rules_per_fw)
        cls.nbr_enabled_fw_rules = (cls.nbr_firewalls *
                                    cls.nbr_enabled_rules_per_fw)
        cls.nbr_fw_rules = cls.nbr_firewalls * cls.nbr_rules_per_fw

        cls.neutron = NeutronTestHelper(Keystone(OSCredentials()))

        print('\n===== Start of tests (%s) =====' % cls.__name__)
        if not Utils.get_env_bool('OS_AUDIT_TEST_SKIP_SETUP'):
            print('\n=== Creating %d firewalls ===' % cls.nbr_firewalls)
            for f in range(cls.nbr_firewalls):
                # create rules
                fw_policy_rule_ids = []
                admin_state_up = cls.admin_state_up()  # repeated query
                print('Creating %d+1 rules for fw %s (admin %s)' % (
                    cls.nbr_enabled_rules_per_fw, f,
                    'up' if admin_state_up else 'down'))
                for r in range(cls.nbr_enabled_rules_per_fw):
                    rule = cls.neutron.create_firewall_rule()
                    cls.fw_rules.append(rule)
                    fw_policy_rule_ids.append(rule['id'])
                # + add 1 disabled rule
                rule = cls.neutron.create_firewall_rule(enabled=False)
                cls.fw_rules.append(rule)
                fw_policy_rule_ids.append(rule['id'])

                # create policy out of the rules
                policy = cls.neutron.create_firewall_policy(
                    'policy', fw_policy_rule_ids)
                cls.fw_policies.append(policy)

                # create router and firewall
                router = cls.neutron.create_router('router')
                cls.routers.append(router)
                cls.fws.append(cls.neutron.create_firewall(
                    policy, router, admin_state_up))
                if admin_state_up:
                    cls.nbr_firewalls_up += 1
                else:
                    cls.nbr_firewalls_down += 1

        print('\n=== Launching system under test')
        cls.main = Main(Utils.TestMainArgs('fwaas',
                                           verbose=verbose,
                                           extreme_verbose=extreme_verbose))

    @classmethod
    def tearDownClass(cls):
        if not cls.nbr_firewalls:
            return  # done

        print('\n===== End of tests (%s) =====' % cls.__name__)
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

    @classmethod
    def admin_state_up(cls):
        raise NotImplementedError

    def assertEqual(self, expected, observed, message=''):
        if expected != observed:
            Reporter('WARN').report(
                'FAIL: expected {}, got {}'.format(expected, observed))
        super(FirewallAuditBase, self).assertEqual(
            expected, observed, message)

    @header()
    def test_firewall_audit(self):
        audit_report, nbr_entities_in_sync = \
            self.main.run() if self.main else ([], 0)

        # expecting zero discrepancies
        self.assertEqual(0, len(audit_report))

        # expecting calculated entities in sync - keeping definition generic
        # so can be reused by derived classes
        expected_nbr_entities_in_sync = (
            self.nbr_firewalls_up +
            2 * self.nbr_firewalls_down +  # these have additional block acl
            self.nbr_firewall_policies +
            self.nbr_enabled_fw_rules)
        self.assertEqual(expected_nbr_entities_in_sync, nbr_entities_in_sync)


class AdminUpFirewallAuditTest(FirewallAuditBase):

    nbr_firewalls = get_nbr_firewalls_under_test()

    @classmethod
    def admin_state_up(cls):
        return True

    @mock.patch.object(VsdClient, 'get_firewalls', return_value=[])
    @mock.patch.object(VsdClient, 'get_firewall_acls', return_value=[])
    @mock.patch.object(VsdClient, 'get_firewall_rules', return_value=[])
    @header()
    def test_firewall_audit_mocked_empty_vsd(self, *_):
        audit_report, nbr_entities_in_sync = self.main.run()

        expected_fw_r_d = self.nbr_firewalls
        expected_acl_d = self.nbr_firewalls
        expected_rules_d = self.nbr_firewalls * self.nbr_enabled_rules_per_fw
        self.assertEqual(
            expected_fw_r_d + expected_acl_d + expected_rules_d,
            len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("ORPHAN_NEUTRON_ENTITY",
                             discrepancy["discrepancy_type"])

        # expecting 0 entities in sync
        self.assertEqual(0, nbr_entities_in_sync)

    @mock.patch.object(Neutron, 'get_firewalls', return_value=[])
    @mock.patch.object(Neutron, 'get_firewall_policies', return_value=[])
    @mock.patch.object(Neutron, 'get_firewall_rules', return_value=[])
    @header()
    def test_firewall_audit_mocked_empty_neutron(self, *_):
        audit_report, nbr_entities_in_sync = self.main.run()

        expected_fw_r_d = self.nbr_firewalls
        expected_acl_d = self.nbr_firewalls
        expected_rules_d = self.nbr_firewalls * self.nbr_enabled_rules_per_fw
        self.assertEqual(
            expected_fw_r_d + expected_acl_d + expected_rules_d,
            len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("ORPHAN_VSD_ENTITY",
                             discrepancy["discrepancy_type"])

        # expecting 0 entities in sync
        self.assertEqual(0, nbr_entities_in_sync)

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
        audit_report, nbr_entities_in_sync = self.main.run()

        expected_rules_d = self.nbr_firewalls * self.nbr_enabled_rules_per_fw
        self.assertEqual(expected_rules_d, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("ENTITY_MISMATCH",
                             discrepancy["discrepancy_type"])
            self.assertEqual("Firewall rule", discrepancy["entity_type"])
            self.assertEqual("('stateful', 'False != True'),"
                             "('action', 'DROP != FORWARD')",
                             discrepancy['discrepancy_details'])

        # expecting calculated entities in sync
        expected_nbr_entities_in_sync = (
            self.nbr_firewalls +
            self.nbr_firewall_policies)
        self.assertEqual(expected_nbr_entities_in_sync, nbr_entities_in_sync)

    def get_firewall_policies_with_reversed_rules(self):
        policies = self.client.list_firewall_policies()['firewall_policies']
        for policy in policies:
            policy['firewall_rules'] = reversed(policy['firewall_rules'])
        return policies

    @mock.patch.object(Neutron, 'get_firewall_policies',
                       get_firewall_policies_with_reversed_rules)
    @header()
    def test_firewall_audit_with_reversed_rule_order_inside_policy(self):
        audit_report, nbr_entities_in_sync = self.main.run()

        expected_rules_d = self.nbr_firewall_policies
        self.assertEqual(expected_rules_d, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("ENTITY_MISMATCH",
                             discrepancy["discrepancy_type"])
            self.assertEqual("Firewall policy", discrepancy["entity_type"])
            self.assertIn('rule_ids', discrepancy["discrepancy_details"])

        # expecting calculated entities in sync
        expected_nbr_entities_in_sync = (
            self.nbr_firewalls +
            self.nbr_enabled_fw_rules)
        self.assertEqual(expected_nbr_entities_in_sync, nbr_entities_in_sync)


class AdminDownFirewallAuditTest(FirewallAuditBase):

    nbr_firewalls = get_nbr_firewalls_under_test()

    @classmethod
    def admin_state_up(cls):
        return False


class AlternatingFirewallStatesAuditTest(FirewallAuditBase):

    nbr_firewalls = get_nbr_firewalls_under_test()
    alternating_admin_state_up = False

    @classmethod
    def admin_state_up(cls):
        cls.alternating_admin_state_up = not cls.alternating_admin_state_up
        return cls.alternating_admin_state_up
