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
from collections import Counter

# system under test
from nuage_openstack_audit.main import Main as SystemUnderTest

# test code
from nuage_openstack_audit.test.tempest_plugin.tests.test_base import TestBase
from nuage_openstack_audit.test.tempest_plugin.tests.utils.main_args \
    import MainArgs
from nuage_openstack_audit.test.tempest_plugin.tests.utils.neutron_topology \
    import NeutronTopology
from nuage_openstack_audit.test.tempest_plugin.tests.utils.vsd_test_helper \
    import VSDTestHelper
from nuage_openstack_audit.utils.logger import Reporter

# run me using:
# python -m testtools.run \
#    nuage_openstack_audit/test/test_sg_audit.py


WARN = Reporter('WARN')
USER = Reporter('USER')
INFO = Reporter('INFO')


class BaseTestCase(object):
    """Wrapper around the base to avoid it being executed standalone"""

    class SgAuditTestBase(TestBase):
        """General integration tests

        Auditing a real system with validation of audit report and
        entities_in_sync. It requires a full OS-VSD setup

        Note that these are sweet spot checks as in essence all what is tested
        here is already tested via mocking ; we are just making sure that a
        life system without any mocking is not giving any new surprise.
        """
        system_under_test = SystemUnderTest(MainArgs('security_group'))

        def __init__(self, *args, **kwargs):
            super(BaseTestCase.SgAuditTestBase, self).__init__(*args, **kwargs)
            self.expected_in_sync = Counter()
            self.sg = None
            self.sg_rule = None
            self.router = None
            self.network = None
            self.subnet = None
            self.port = None
            self.port_no_sg = None
            self.port_port_security_disabled = None

        @classmethod
        def setUpClass(cls):
            # VSD
            cls.vsd = VSDTestHelper(SystemUnderTest.get_cms_id())
            cls.vsd.authenticate(SystemUnderTest.get_vsd_credentials())

            # Neutron
            cls.topology = NeutronTopology()
            cls.topology.authenticate(SystemUnderTest.get_os_credentials(),
                                      db_access=True)

        def tearDown(self):
            super(BaseTestCase.SgAuditTestBase, self).tearDown()
            self.topology.teardown()

        def test_port_security_mismatch_neutron_disabled(self):
            """Port security disabled in neutron but enabled on VSD"""
            if self.topology.is_dhcp_agent_enabled():
                self.skipTest("Running this test with DHCP agent enabled is "
                              "not supported")
            self.assert_healthy_setup()

            # Change port_security_enabled in neutron database
            self.topology.disable_port_security_in_db(self.port_no_sg['id'])

            # Audit again
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            self.assert_audit_report_length(1, audit_report)
            discrepancy = audit_report[0]
            self.assertEqual('A Neutron port with port security disabled '
                             'exists but there is no policy group for less '
                             'security in its domain.',
                             discrepancy['discrepancy_details'])
            self.assertEqual(self.port_no_sg['id'],
                             discrepancy['neutron_entity'])
            self.assertEqual(discrepancy['discrepancy_type'],
                             'ORPHAN_NEUTRON_ENTITY')
            self.assertEqual(discrepancy['entity_type'], 'port')
            domain_getter = (
                self.vsd.vspk_helper.get_default_enterprise().domains
                if self.router
                else self.vsd.vspk_helper.get_default_enterprise().l2_domains)
            domain_os_id = (self.router['id'] if self.router
                            else self.subnet['network_id'])
            domain_filter = (self.vsd.vspk_helper
                             .get_external_id_filter(domain_os_id))
            domain = (domain_getter.get_first(filter=domain_filter))
            self.assertEqual(domain.id, discrepancy['vsd_entity'])

            self.assert_counter_equal(self.expected_in_sync, observed_in_sync)

            # Revert database change
            self.topology.enable_port_security_in_db(self.port_no_sg['id'])

        def test_port_security_mismatch_neutron_enabled(self):
            """Port security enabled in neutron but disabled on VSD"""
            if self.topology.is_dhcp_agent_enabled():
                self.skipTest("Running this test with DHCP agent enabled is "
                              "not supported")

            self._create_port_security_disabled()

            self.assert_healthy_setup()

            # Change port_security_enabled in neutron database
            self.topology.enable_port_security_in_db(
                self.port_port_security_disabled['id'])

            # Audit again
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            self.assert_audit_report_length(1, audit_report)
            discrepancy = audit_report[0]

            self.assertEqual('Policygroup for less security exists in VSD but '
                             'there are no neutron ports with port security '
                             'disabled', discrepancy['discrepancy_details'])
            self.assertEqual(discrepancy['discrepancy_type'],
                             'ORPHAN_VSD_ENTITY')
            self.assertEqual(discrepancy['entity_type'], 'Policygroup')
            self.assertIsNone(discrepancy['neutron_entity'])

            # Check vsd entity, should be the PG_FOR_LESS_SECURITY
            domain_getter = (
                self.vsd.vspk_helper.get_default_enterprise().domains
                if self.router
                else self.vsd.vspk_helper.get_default_enterprise().l2_domains)
            domain_os_id = (self.router['id'] if self.router
                            else self.subnet['network_id'])
            domain_filter = (self.vsd.vspk_helper
                             .get_external_id_filter(domain_os_id))
            domain = (domain_getter.get_first(filter=domain_filter))
            pg_for_less = [pg.id for pg in
                           self.vsd.get_policy_groups(
                               domain,
                               "name BEGINSWITH 'PG_FOR_LESS_SECURITY'")]
            self.assertIn(discrepancy['vsd_entity'], pg_for_less)

            # Revert database change
            self.topology.disable_port_security_in_db(
                self.port_port_security_disabled['id'])

        def test_missing_rule(self):
            if self.topology.is_dhcp_agent_enabled():
                self.skipTest("Running this test with DHCP agent enabled is "
                              "not supported")
            self.assert_healthy_setup()

            # Delete some acl entry
            f = (self.vsd.vspk_helper
                 .get_external_id_filter(self.sg_rule['id']))
            some_acl_entry = (self.vsd.vspk_helper.session.user.
                              ingress_acl_entry_templates.get_first(filter=f))
            self.assertIsNotNone(some_acl_entry)
            some_acl_entry.delete()

            # Audit again, expecting an ORPHAN_NEUTRON_ENTITY
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            expected_in_sync = Counter(self.expected_in_sync)
            expected_in_sync['ingress_acl_entry_templates'] -= 1
            self.assert_counter_equal(expected_in_sync, observed_in_sync)
            self.assert_audit_report_length(1, audit_report)
            discrepancy = audit_report[0]
            self.assertEqual('ORPHAN_NEUTRON_ENTITY',
                             discrepancy['discrepancy_type'])
            self.assertEqual('Security Group Rule', discrepancy['entity_type'])
            self.assertEqual(self.sg_rule['id'],
                             discrepancy['neutron_entity'])
            self.assertIsNone(discrepancy['vsd_entity'])

        def _get_vport(self):
            # Get vPort
            domain_getter = (
                self.vsd.vspk_helper.get_default_enterprise().domains
                if self.router
                else self.vsd.vspk_helper.get_default_enterprise().l2_domains)
            domain_os_id = (self.router['id'] if self.router
                            else self.subnet['network_id'])
            domain_filter = (self.vsd.vspk_helper
                             .get_external_id_filter(domain_os_id))
            domain = (domain_getter.get_first(filter=domain_filter))

            vport_filter = (self.vsd.vspk_helper
                            .get_external_id_filter(self.port['id']))
            return domain.vports.get_first(filter=vport_filter)

        def _create_port_security_disabled(self):
            self.port_port_security_disabled = self.topology.create_port(
                self.network, port_security_enabled=False,
                name='port-security-disabled')

            self.expected_in_sync.update({
                'ingress_acl_entry_templates (PG_FOR_LESS)':
                    2 * self.topology.counter['ports_security_disabled'],
                'egress_acl_entry_templates (PG_FOR_LESS)':
                    2 * self.topology.counter['ports_security_disabled'],
                'vports (PG_FOR_LESS)':
                    self.topology.counter['ports_security_disabled']
            })

        def test_missing_vport_to_pg_mapping(self):
            if self.topology.is_dhcp_agent_enabled():
                self.skipTest("Running this test with DHCP agent enabled is "
                              "not supported")
            self.assert_healthy_setup()

            vport = self._get_vport()

            # Remove vPort-pg mapping
            vport.assign([], self.vsd.vspk_helper.vspk.NUPolicyGroup)

            # Audit again
            audit_report, observed_in_sync = self.system_under_test.audit_sg()

            nr_sg_on_port = len(self.port['security_groups'])
            expected_in_sync = Counter(self.expected_in_sync)
            expected_in_sync['vports'] = (expected_in_sync['vports'] -
                                          nr_sg_on_port)
            self.assert_counter_equal(expected_in_sync, observed_in_sync)
            self.assert_audit_report_length(nr_sg_on_port, audit_report)
            # note that the exact same discrepancy is reported if there are
            # multiple sgs on the port, we might want to change this
            for i in range(nr_sg_on_port):
                discrepancy = audit_report[i]
                self.assertEqual('ORPHAN_NEUTRON_ENTITY',
                                 discrepancy['discrepancy_type'])
                self.assertEqual('Security Group port',
                                 discrepancy['entity_type'])
                self.assertEqual(self.port['id'],
                                 discrepancy['neutron_entity'])
                self.assertIsNone(discrepancy['vsd_entity'])

        def test_missing_pg(self):
            if self.topology.is_dhcp_agent_enabled():
                self.skipTest("Running this test with DHCP agent enabled is "
                              "not supported")
            self.assert_healthy_setup()

            vport = self._get_vport()
            pgs = vport.policy_groups.get()

            # Remove vPorts-pg link so we can delete the pgs
            vport.assign([], self.vsd.vspk_helper.vspk.NUPolicyGroup)

            # Delete the pgs of the vPort
            for pg in pgs:
                pg.delete()

            # Audit again
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            self.assert_audit_report_length(len(self.port['security_groups']),
                                            audit_report)

            for discrepancy in audit_report:
                self.assertEqual('ORPHAN_NEUTRON_ENTITY',
                                 discrepancy['discrepancy_type'])
                self.assertEqual('Security Group', discrepancy['entity_type'])
                self.assertIn(discrepancy['neutron_entity'],
                              self.port['security_groups'])
                self.assertIsNone(discrepancy['vsd_entity'])

            # assert that all the neutron entities are different
            neutron_entities = [discrepancy['neutron_entity']
                                for discrepancy in audit_report]
            self.assertEqual(len(neutron_entities), len(set(neutron_entities)))

        def test_orphan_acl_entry(self):
            if self.topology.is_dhcp_agent_enabled():
                self.skipTest("Running this test with DHCP agent enabled is "
                              "not supported")
            self.assert_healthy_setup()

            # Create some egress acl entry
            acl_filter = (self.vsd.vspk_helper.get_external_id_filter(
                self.router['id'] if self.router
                else self.subnet['network_id']))
            egress_acl = (self.vsd.vspk_helper.session.user.
                          egress_acl_templates.get_first(filter=acl_filter))
            pg_filter = (self.vsd.vspk_helper
                         .get_external_id_filter(self.sg['id']))
            pg = (self.vsd.vspk_helper.session.user.
                  policy_groups.get_first(filter=pg_filter))
            new_acl_entry = self.vsd.create_egress_acl_entry(
                dscp="*", action="FORWARD", ether_type='0x0800',
                external_id=(self.vsd.vspk_helper
                             .get_external_id('clearly_nonexisting')),
                protocol='1',
                location_type='POLICYGROUP', location_id=pg.id)
            egress_acl.create_child(new_acl_entry)

            # Audit again, expecting an ORPHAN_VSD_ENTITY
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            self.assert_counter_equal(self.expected_in_sync, observed_in_sync)
            self.assert_audit_report_length(1, audit_report)
            discrepancy = audit_report[0]
            self.assertEqual('ORPHAN_VSD_ENTITY',
                             discrepancy['discrepancy_type'])
            self.assertEqual('Security Group Rule', discrepancy['entity_type'])
            self.assertEqual(new_acl_entry.id, discrepancy['vsd_entity'])
            self.assertIsNone(discrepancy['neutron_entity'])

        def test_mismatch_rule(self):
            if self.topology.is_dhcp_agent_enabled():
                self.skipTest("Running this test with DHCP agent enabled is "
                              "not supported")
            self.assert_healthy_setup()

            # Modify some acl entry
            f = (self.vsd.vspk_helper
                 .get_external_id_filter(self.sg_rule['id']))
            some_acl_entry = (self.vsd.vspk_helper.session.user.
                              ingress_acl_entry_templates.get_first(filter=f))
            self.assertIsNotNone(some_acl_entry)
            self.assertEqual(some_acl_entry.protocol, '47')  # 47 = GRE
            some_acl_entry.protocol = '17'  # 17 = UDP
            some_acl_entry.source_port = 8080  # must be set for UDP
            some_acl_entry.destination_port = 9090  # must be set for UDP
            some_acl_entry.save()

            # Audit again, expecting an ENTITY_MISMATCH
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            expected_in_sync = Counter(self.expected_in_sync)
            expected_in_sync['ingress_acl_entry_templates'] -= 1
            self.assert_counter_equal(expected_in_sync, observed_in_sync)
            self.assert_audit_report_length(1, audit_report)
            discrepancy = audit_report[0]
            self.assertEqual('ENTITY_MISMATCH',
                             discrepancy['discrepancy_type'])
            self.assertEqual('Security Group Rule', discrepancy['entity_type'])
            self.assertEqual(self.sg_rule['id'],
                             discrepancy['neutron_entity'])
            self.assertEqual(some_acl_entry.id, discrepancy['vsd_entity'])

        def assert_healthy_setup(self):
            # Expect no discrepancies
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            self.assert_counter_equal(self.expected_in_sync, observed_in_sync)
            self.assert_audit_report_length(0, audit_report)


class SgAuditTestL2(BaseTestCase.SgAuditTestBase):
    """Tests with an L2 setup"""

    def __init__(self, *args, **kwargs):
        super(SgAuditTestL2, self).__init__(*args, **kwargs)

    def setUp(self):
        super(SgAuditTestL2, self).setUp()

        # Create a small topology
        self.sg = self.topology.create_security_group_used(name="test-sg")
        self.sg_rule = self.topology.create_security_group_rule_stateful(
            protocol='gre', security_group_id=self.sg['id'],
            ethertype='IPv4', direction='egress',
            remote_ip_prefix='0.0.0.0/0')
        self.topology.create_security_group_rule_stateful(
            protocol='tcp', security_group_id=self.sg['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0')
        self.network = self.topology.create_network(name='test-network')
        self.subnet = self.topology.create_subnet_l2(
            network_id=self.network['id'],
            ip_version=4,
            cidr='10.0.0.0/24')
        self.port = self.topology.create_port(
            self.network, security_groups=[self.sg['id']],
            name='normal_port1')
        self.port_no_sg = self.topology.create_port(
            self.network, security_groups=[],  # if sgs -> os invalid state
            name='port_no_sg')

        self.expected_in_sync = Counter({
            'egress_acl_entry_templates':
                self.topology.counter['sg_rules_ingress'],
            'ingress_acl_entry_templates':
                self.topology.counter['sg_rules_egress'],
            'policygroups':
                self.topology.counter['sgs'],
            'vports': self.topology.counter['ports_sg']})


class SgAuditTestL3(BaseTestCase.SgAuditTestBase):
    """Tests with an L3 setup"""

    def __init__(self, *args, **kwargs):
        super(SgAuditTestL3, self).__init__(*args, **kwargs)

    def setUp(self):
        super(SgAuditTestL3, self).setUp()

        # Create a small topology
        self.sg = self.topology.create_security_group_used(name="test-sg")
        self.sg_rule = self.topology.create_security_group_rule_stateful(
            protocol='gre', security_group_id=self.sg['id'],
            ethertype='IPv4', direction='egress',
            remote_ip_prefix='0.0.0.0/0')
        self.topology.create_security_group_rule_stateful(
            protocol='tcp', security_group_id=self.sg['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0')
        self.router = self.topology.create_router(name='test-router')
        self.network = self.topology.create_network(name='test-network')
        self.subnet = self.topology.create_subnet_l3(
            network_id=self.network['id'],
            ip_version=4,
            cidr='10.0.0.0/24')
        self.topology.create_router_interface(router_id=self.router['id'],
                                              subnet_id=self.subnet['id'])
        self.port = self.topology.create_port(
            self.network, security_groups=[self.sg['id']],
            name='normal_port1')
        self.port_no_sg = self.topology.create_port(
            self.network, security_groups=[],  # if sgs -> os invalid state
            name='port_no_sg')

        self.expected_in_sync = Counter({
            'egress_acl_entry_templates':
                self.topology.counter['sg_rules_ingress'],
            'ingress_acl_entry_templates':
                self.topology.counter['sg_rules_egress'],
            'policygroups':
                self.topology.counter['sgs'],
            'vports': self.topology.counter['ports_sg']
        })


class SgAuditTestManyToMany(BaseTestCase.SgAuditTestBase):
    """Sg attached to multiple ports and port attached to multiple sgs"""

    def __init__(self, *args, **kwargs):
        super(SgAuditTestManyToMany, self).__init__(*args, **kwargs)

    def setUp(self):
        super(SgAuditTestManyToMany, self).setUp()

        # Security groups
        self.sg = self.topology.create_security_group_used(name="test-sg")
        sg2 = self.topology.create_security_group_used(name="test-sg-2")

        # Security group rules
        self.sg_rule = self.topology.create_security_group_rule_stateful(
            protocol='gre', security_group_id=self.sg['id'],
            ethertype='IPv4', direction='egress',
            remote_ip_prefix='10.0.0.0/24')
        self.topology.create_security_group_rule_stateful(
            protocol='tcp', security_group_id=sg2['id'],
            ethertype='IPv4', direction='egress',
            remote_ip_prefix='11.0.0.0/24')
        self.topology.create_security_group_rule_stateful(
            protocol='tcp', security_group_id=sg2['id'],
            ethertype='IPv4', direction='egress',
            remote_ip_prefix='12.0.0.0/24')

        self.router = self.topology.create_router(name='test-router')
        self.network = self.topology.create_network(name='test-network')
        self.subnet = self.topology.create_subnet_l3(
            network_id=self.network['id'],
            ip_version=4,
            cidr='10.0.0.0/24')
        subnet2 = self.topology.create_subnet_l3(
            network_id=self.network['id'],
            ip_version=4,
            cidr='11.0.0.0/24')
        self.topology.create_router_interface(router_id=self.router['id'],
                                              subnet_id=self.subnet['id'])
        self.topology.create_router_interface(router_id=self.router['id'],
                                              subnet_id=subnet2['id'])

        self.port = self.topology.create_port(
            self.network, security_groups=[self.sg['id'], sg2['id']],
            name='port_subnet1', fixed_ips=[{'subnet_id': self.subnet['id']}])
        self.topology.create_port(
            self.network, security_groups=[self.sg['id']],
            name='port_subnet2', fixed_ips=[{'subnet_id': subnet2['id']}])
        self.port_no_sg = self.topology.create_port(
            self.network, security_groups=[],  # if sgs -> os invalid state
            name='port_no_sg')

        # these vports will be in sync twice because they are in two sgs
        nr_ports_in_two_sgs = 1

        self.expected_in_sync = Counter({
            'egress_acl_entry_templates':
                self.topology.counter['sg_rules_ingress'],
            'ingress_acl_entry_templates':
                self.topology.counter['sg_rules_egress'],
            'policygroups':
                self.topology.counter['sgs'],
            'vports': self.topology.counter['ports_sg'] + nr_ports_in_two_sgs
        })


class NoDiscrepancies(TestBase):
    """Test that there are no discrepancies

    Auditing a real system with validation of audit report and
    entities_in_sync. It requires a full OS-VSD setup
    """
    system_under_test = SystemUnderTest(MainArgs('security_group'))

    @classmethod
    def setUpClass(cls):
        cls.topology = NeutronTopology()
        cls.topology.authenticate(SystemUnderTest.get_os_credentials())

    def test_domain_dependent_pg_for_less(self):
        network = self.topology.create_network(name='test-network')
        subnet = self.topology.create_subnet_l2(
            network_id=network['id'],
            ip_version=4,
            cidr='10.0.0.0/24')
        # Create port that will end up in PG_FOR_LESS_SECURITY
        self.topology.create_port(
            network, port_security_enabled=False, name='port_no_security')
        router = self.topology.create_router(name='test-router')

        # Convert L2 domain to L3
        self.topology.create_router_interface(
            router_id=router['id'], subnet_id=subnet['id'])

        # Create a ports which will end up in a different PG_FOR_LESS_SECURITY
        self.topology.create_port(
            network, port_security_enabled=False, name='port_no_security')

        # Expect no discrepancies
        # Two PG_FOR_LESS_SECURITY, one for the old vPort, one for the new
        expected_in_sync = Counter({
            'ingress_acl_entry_templates (PG_FOR_LESS)': 4,
            'egress_acl_entry_templates (PG_FOR_LESS)': 4,
            'vports (PG_FOR_LESS)': 2
        })
        audit_report, observed_in_sync = self.system_under_test.audit_sg()
        self.assert_counter_equal(expected_in_sync, observed_in_sync)
        self.assert_audit_report_length(0, audit_report)

    def tearDown(self):
        super(NoDiscrepancies, self).tearDown()
        self.topology.teardown()
