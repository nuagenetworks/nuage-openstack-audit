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

from nuage_openstack_audit.audit import Audit
from nuage_openstack_audit.osclient.osclient import Neutron
from nuage_openstack_audit.osclient.osclient import OSClient
from nuage_openstack_audit.utils.utils import get_env_bool
from nuage_openstack_audit.utils.utils import get_env_var
from nuage_openstack_audit.vsdclient.impl.vsdclientimpl import VsdClientImpl

# run me using:
# python -m testtools.run nuage_openstack_audit/test/audit_test.py

# *****************************************************************************
#  CAUTION : THIS IS NOT A REAL UNIT TEST ; IT REQUIRES A FULL OS-VSD SETUP,
#            SETUP WITH ENV VARIABLES FOR OS AUDIT CORRECTLY SET
# *****************************************************************************


def header():
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            if f.func_code.co_name != 'wrapper':
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


class AuditTest(testtools.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.neutron = OSClient().neutron()
        cls.os_auditor = Audit(report_file='None')

        cls.routers = []
        cls.fws = []
        cls.fw_policies = []
        cls.fw_rules = []

        cls.nr_firewalls = int(
            get_env_var('OS_AUDIT_TEST_NR_FIREWALLS', 2))
        cls.nr_rules_per_fw = cls.nr_firewalls - 1  # 1 rule is added on top

        print('\n===== Start of tests =====')
        if not get_env_bool('OS_AUDIT_TEST_SKIP_SETUP'):
            print('\n=== Creating %d firewalls ===' % cls.nr_firewalls)
            for f in range(cls.nr_firewalls):
                fw_policy_rule_ids = []
                print('Creating %d+1 rules for fw %s' % (
                    cls.nr_rules_per_fw, f))
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
                cls.fws.append(cls.neutron.create_firewall(policy, router))

    def setUp(self):
        super(AuditTest, self).setUp()

        # make sure every test has new report
        # and make sure there is at least 1 sec in between tests
        time.sleep(1)
        self.os_auditor.set_report_name(
            suffix=time.strftime('%d-%m-%Y_%H:%M:%S'))

    @classmethod
    def tearDownClass(cls):
        print('\n===== End of tests =====')
        if not get_env_bool('OS_AUDIT_TEST_SKIP_TEARDOWN'):
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

    @header()
    def test_firewall_audit(self):
        audit_report = self.os_auditor.do_audit('fwaas')

        # expecting zero discrepancies :
        self.assertEqual(0, len(audit_report))

    @mock.patch.object(VsdClientImpl, 'get_firewalls',
                       return_value=[])
    @mock.patch.object(VsdClientImpl, 'get_firewall_policies',
                       return_value=[])
    @mock.patch.object(VsdClientImpl, 'get_firewall_rules',
                       return_value=[])
    @mock.patch.object(VsdClientImpl, 'get_firewall_rules_by_policy',
                       return_value=[])
    @mock.patch.object(VsdClientImpl, 'get_firewall_rules_by_ids',
                       return_value=[])
    @header()
    def test_firewall_audit_mocked_empty_vsd(self, *_):
        audit_report = self.os_auditor.do_audit('fwaas')

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
        audit_report = self.os_auditor.do_audit('fwaas')

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
        audit_report = self.os_auditor.do_audit('fwaas')

        expected_rules_d = self.nr_firewalls * self.nr_rules_per_fw
        self.assertEqual(expected_rules_d, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual("('stateful', 'False != True'),"
                             "('action', 'DROP != FORWARD')",
                             discrepancy['discrepancy_details'])
            self.assertEqual("ENTITY_MISMATCH",
                             discrepancy["discrepancy_type"])
            self.assertEqual("Firewall rule", discrepancy["entity_type"])
