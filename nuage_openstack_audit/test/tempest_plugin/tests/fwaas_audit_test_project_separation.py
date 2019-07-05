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
import mock

# system under test
from nuage_openstack_audit.main import Main  # system under test
from nuage_openstack_audit.osclient.osclient import KeystoneClient
from nuage_openstack_audit.osclient.osclient import NeutronClient  # f/ mocking
from nuage_openstack_audit.vsdclient.vsdclient import VsdClient  # for mocking

# test code
from nuage_openstack_audit.test.tempest_plugin.tests.test_base import TestBase
from nuage_openstack_audit.test.tempest_plugin.tests.utils.decorators \
    import header
from nuage_openstack_audit.test.tempest_plugin.tests.utils.main_args \
    import MainArgs
from nuage_openstack_audit.test.tempest_plugin.tests.utils.neutron_topology \
    import NeutronTopology
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.utils import Utils

# run me using:
# python -m testtools.run
#     nuage_openstack_audit/test/fwaas_audit_test_project_separation.py

# *****************************************************************************
#  CAUTION : THIS IS NOT A REAL UNIT TEST ; IT REQUIRES A FULL OS-VSD SETUP,
#            SETUP WITH AUDIT ENV VARIABLES CORRECTLY SET.
# *****************************************************************************

USER = Reporter('USER')


def get_nbr_firewalls_under_test():
    return 6


class FirewallAuditProjectSeparationBase(TestBase):

    main = None

    neutron = None
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
        super(FirewallAuditProjectSeparationBase, cls).setUpClass()
        if not cls.nbr_firewalls:
            return  # done

        cls.routers = []
        cls.fws = []
        cls.fw_policies = []
        cls.fw_rules = []

        cls.nbr_firewalls_up = 0  # incremented below, but important to reset
        cls.nbr_firewalls_down = 0  # incremented below
        cls.nbr_firewall_policies = cls.nbr_firewalls
        cls.nbr_enabled_rules_per_fw = cls.nbr_firewalls / 2 - 1
        cls.nbr_disabled_rules_per_fw = 1
        cls.nbr_rules_per_fw = (cls.nbr_enabled_rules_per_fw +
                                cls.nbr_disabled_rules_per_fw)
        cls.nbr_enabled_fw_rules = (cls.nbr_firewalls *
                                    cls.nbr_enabled_rules_per_fw)
        cls.nbr_fw_rules = cls.nbr_firewalls * cls.nbr_rules_per_fw

        USER.report('\n===== Start of tests (%s) =====', cls.__name__)

        if not Utils.get_env_bool('OS_AUDIT_TEST_SKIP_SETUP'):
            cls.neutron = NeutronTopology()
            cls.neutron.authenticate(Main.get_os_credentials())
            cls.keystone = KeystoneClient()
            cls.keystone.authenticate(Main.get_os_credentials())
            USER.report('\n=== Creating Keystone Project1 and Project2 ===')
            cls.project1 = cls.keystone.client.projects.create(
                'test-project1-fw', 'default')
            cls.project2 = cls.keystone.client.projects.create(
                'test-project2-fw', 'default')

            USER.report('\n=== Creating %d OpenStack firewalls ===',
                        cls.nbr_firewalls)
            for f in range(cls.nbr_firewalls / 2):
                # create rules
                fw_policy_rule_ids_project1 = []
                fw_policy_rule_ids_project2 = []
                admin_state_up = cls.admin_state_up()  # repeated query
                print('Creating %d+1 OpenStack firewall rules for fw %s and %s'
                      ' (admin %s)' % (cls.nbr_enabled_rules_per_fw, 2 * f,
                                       2 * f + 1,
                                       'up' if admin_state_up else 'down'))
                for r in range(cls.nbr_enabled_rules_per_fw):
                    rule = cls.neutron.create_firewall_rule(
                        project_id=cls.project1.id)
                    cls.fw_rules.append(rule)
                    fw_policy_rule_ids_project1.append(rule['id'])
                    rule = cls.neutron.create_firewall_rule(
                        project_id=cls.project2.id)
                    cls.fw_rules.append(rule)
                    fw_policy_rule_ids_project2.append(rule['id'])

                # + add 1 disabled rule
                rule = cls.neutron.create_firewall_rule(
                    enabled=False, project_id=cls.project1.id)
                cls.fw_rules.append(rule)
                fw_policy_rule_ids_project1.append(rule['id'])
                rule = cls.neutron.create_firewall_rule(
                    enabled=False, project_id=cls.project2.id)
                cls.fw_rules.append(rule)
                fw_policy_rule_ids_project2.append(rule['id'])

                # create policy out of the rules
                policy_project1 = cls.neutron.create_firewall_policy(
                    'policy', fw_policy_rule_ids_project1,
                    project_id=cls.project1.id)
                cls.fw_policies.append(policy_project1)
                policy_project2 = cls.neutron.create_firewall_policy(
                    'policy', fw_policy_rule_ids_project2,
                    project_id=cls.project2.id)
                cls.fw_policies.append(policy_project2)

                # create router and firewall
                router_project1 = cls.neutron.create_router(
                    'router-project1', project_id=cls.project1.id)
                cls.routers.append(router_project1)
                router_project2 = cls.neutron.create_router(
                    'router-project2', project_id=cls.project2.id)
                cls.routers.append(router_project2)
                fw = cls.neutron.create_firewall(
                    policy_project1, router_project1, admin_state_up,
                    project_id=cls.project1.id)
                cls.fws.append(fw)
                fw = cls.neutron.create_firewall(
                    policy_project2, router_project2, admin_state_up,
                    project_id=cls.project2.id)
                cls.fws.append(fw)
                if admin_state_up:
                    cls.nbr_firewalls_up += 2
                else:
                    cls.nbr_firewalls_down += 2

        USER.report('\n=== Launching system under test ===')
        cls.sut = Main(MainArgs('security_group'))
        cls.sut_project_1 = Main(MainArgs(
            'fwaas', project=cls.project1.id))
        cls.sut_project_2 = Main(MainArgs(
            'fwaas', project=cls.project2.id))

    @classmethod
    def tearDownClass(cls):
        super(FirewallAuditProjectSeparationBase, cls).tearDownClass()
        if not cls.nbr_firewalls:
            return  # done

        USER.report('\n===== End of tests (%s) =====', cls.__name__)
        if not Utils.get_env_bool('OS_AUDIT_TEST_SKIP_TEARDOWN'):
            cls.neutron.teardown()
            cls.keystone.client.projects.delete(cls.project1.id)
            cls.keystone.client.projects.delete(cls.project2.id)

    @classmethod
    def admin_state_up(cls):
        raise NotImplementedError

    @header()
    def test_firewall_audit(self):
        audit_report, observed_in_sync = self.sut.audit_fwaas()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_fwaas()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_fwaas()

        # expecting zero discrepancies
        self.assert_audit_report_length(0, audit_report)
        self.assert_audit_report_length(0, audit_report1)
        self.assert_audit_report_length(0, audit_report2)

        # expecting calculated entities in sync - keeping definition generic
        # so can be reused by derived classes
        expected_nbr_entities_in_sync = (
            self.nbr_firewalls_up +
            2 * self.nbr_firewalls_down +  # these have additional block acl
            self.nbr_firewall_policies +
            self.nbr_enabled_fw_rules)

        self.assert_entities_in_sync(expected_nbr_entities_in_sync,
                                     observed_in_sync)
        self.assert_entities_in_sync(expected_nbr_entities_in_sync / 2,
                                     observed_in_sync1)
        self.assert_entities_in_sync(expected_nbr_entities_in_sync / 2,
                                     observed_in_sync2)

    @header()
    def test_firewall_audit_project_user(self):
        os_credentials = self.sut.get_os_credentials()
        user1 = self.keystone.client.users.create(
            'user-project1', project=self.project1,
            password=os_credentials.password)
        os_credentials.project_name = self.project1.name
        os_credentials.username = user1.name

        role = next(role for role in self.keystone.client.roles.list() if
                    role.name == 'Member')
        self.keystone.client.roles.grant(role, user=user1,
                                         project=self.project1)
        sut_user1 = Main(MainArgs(
            'fwaas', project=self.project1.id))
        sut_user1.neutron = sut_user1.get_neutron_client(os_credentials,
                                                         self.project1.id)
        audit_report, observed_in_sync = sut_user1.audit_fwaas()
        self.keystone.client.users.delete(user1.id)
        self.assert_audit_report_length(0, audit_report)
        expected_nbr_entities_in_sync = (
            self.nbr_firewalls_up +
            2 * self.nbr_firewalls_down +  # these have additional block acl
            self.nbr_firewall_policies +
            self.nbr_enabled_fw_rules)

        self.assert_entities_in_sync(expected_nbr_entities_in_sync / 2,
                                     observed_in_sync)


class AdminUpFirewallAuditProjectSeparationTest(
        FirewallAuditProjectSeparationBase):

    nbr_firewalls = get_nbr_firewalls_under_test()

    @classmethod
    def admin_state_up(cls):
        return True

    @mock.patch.object(VsdClient, 'get_firewalls', return_value=[])
    @mock.patch.object(VsdClient, 'get_firewall_acls', return_value=[])
    @mock.patch.object(VsdClient, 'get_firewall_rules', return_value=[])
    @header()
    def test_firewall_audit_mocked_empty_vsd(self, *_):
        audit_report, observed_in_sync = self.sut.audit_fwaas()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_fwaas()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_fwaas()

        expected_fw_r_d = self.nbr_firewalls
        expected_acl_d = self.nbr_firewalls
        expected_rules_d = self.nbr_firewalls * self.nbr_enabled_rules_per_fw
        expected_discrepancies = (expected_fw_r_d + expected_acl_d +
                                  expected_rules_d)
        self.assert_audit_report_length(expected_discrepancies, audit_report)
        self.assert_audit_report_length(expected_discrepancies / 2,
                                        audit_report1)
        self.assert_audit_report_length(expected_discrepancies / 2,
                                        audit_report2)
        for discrepancy in audit_report + audit_report1 + audit_report2:
            self.assert_equal('ORPHAN_NEUTRON_ENTITY',
                              discrepancy["discrepancy_type"])

        self.assert_entities_in_sync(0, observed_in_sync)
        self.assert_entities_in_sync(0, observed_in_sync1)
        self.assert_entities_in_sync(0, observed_in_sync2)

    def get_firewall_rules_with_action_deny(self, **kwargs):
        if self.project_id:
            kwargs['project_id'] = self.project_id
        rules = self.client.list_firewall_rules(**kwargs)['firewall_rules']

        for r in rules:
            r['action'] = 'deny'
        return rules

    @mock.patch.object(NeutronClient, 'get_firewall_rules',
                       get_firewall_rules_with_action_deny)
    @header()
    def test_firewall_audit_with_rules_having_action_mismatch(self):
        audit_report, observed_in_sync = self.sut.audit_fwaas()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_fwaas()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_fwaas()

        expected_discrepancies = (self.nbr_firewalls *
                                  self.nbr_enabled_rules_per_fw)
        self.assert_audit_report_length(expected_discrepancies, audit_report)
        self.assert_audit_report_length(expected_discrepancies / 2,
                                        audit_report1)
        self.assert_audit_report_length(expected_discrepancies / 2,
                                        audit_report2)
        for discrepancy in audit_report + audit_report1 + audit_report2:
            self.assert_equal('ENTITY_MISMATCH',
                              discrepancy['discrepancy_type'])
            self.assert_equal('Firewall rule', discrepancy["entity_type"])
            self.assertIn("('stateful', 'False != True')",
                          discrepancy['discrepancy_details'])
            self.assertIn("('action', 'DROP != FORWARD')",
                          discrepancy['discrepancy_details'])

        # expecting calculated entities in sync
        expected_nbr_entities_in_sync = (
            self.nbr_firewalls +
            self.nbr_firewall_policies)
        self.assert_entities_in_sync(expected_nbr_entities_in_sync,
                                     observed_in_sync)
        self.assert_entities_in_sync(expected_nbr_entities_in_sync / 2,
                                     observed_in_sync1)
        self.assert_entities_in_sync(expected_nbr_entities_in_sync / 2,
                                     observed_in_sync2)

    def get_firewall_policies_with_reversed_rules(self, **params):
        if self.project_id:
            params['project_id'] = self.project_id
        policies = self.client.list_firewall_policies(
            **params)['firewall_policies']
        for policy in policies:
            policy['firewall_rules'] = reversed(policy['firewall_rules'])
        return policies

    @mock.patch.object(NeutronClient, 'get_firewall_policies',
                       get_firewall_policies_with_reversed_rules)
    @header()
    def test_firewall_audit_with_reversed_rule_order_inside_policy(self):
        audit_report, observed_in_sync = self.sut.audit_fwaas()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_fwaas()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_fwaas()

        expected_discrepancies = self.nbr_firewall_policies
        self.assert_audit_report_length(expected_discrepancies, audit_report)
        self.assert_audit_report_length(expected_discrepancies / 2,
                                        audit_report1)
        self.assert_audit_report_length(expected_discrepancies / 2,
                                        audit_report2)
        for discrepancy in audit_report + audit_report1 + audit_report2:
            self.assert_equal('ENTITY_MISMATCH',
                              discrepancy["discrepancy_type"])
            self.assert_equal('Firewall policy', discrepancy['entity_type'])
            self.assert_in('rule_ids', discrepancy['discrepancy_details'])

        # expecting calculated entities in sync
        expected_in_sync = (
            self.nbr_firewalls +
            self.nbr_enabled_fw_rules)
        self.assert_entities_in_sync(expected_in_sync, observed_in_sync)
        self.assert_entities_in_sync(expected_in_sync / 2, observed_in_sync1)
        self.assert_entities_in_sync(expected_in_sync / 2, observed_in_sync2)


class AdminDownFirewallAuditProjectSeparationTest(
        FirewallAuditProjectSeparationBase):

    nbr_firewalls = get_nbr_firewalls_under_test()

    @classmethod
    def admin_state_up(cls):
        return False


class AlternatingFirewallStatesAuditProjectSeparationTest(
        FirewallAuditProjectSeparationBase):

    nbr_firewalls = get_nbr_firewalls_under_test()
    alternating_admin_state_up = False

    @classmethod
    def admin_state_up(cls):
        cls.alternating_admin_state_up = not cls.alternating_admin_state_up
        return cls.alternating_admin_state_up
