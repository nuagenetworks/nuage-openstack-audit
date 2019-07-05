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
import mock
import random

# system under test
from nuage_openstack_audit.main import Main as SystemUnderTest
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
from nuage_openstack_audit.test.tempest_plugin.tests.utils.vsd_test_helper \
    import VSDTestHelper
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.vsdclient.common.vspk_helper import VspkHelper

# run me using:
# python -m testtools.run \
#   nuage_openstack_audit/test/test_sg_audit_by_mocking.py


WARN = Reporter('WARN')
USER = Reporter('USER')
INFO = Reporter('INFO')


class Topology1(NeutronTopology):
    def __init__(self):
        super(Topology1, self).__init__()

        # vsd entities
        self.vsd = VSDTestHelper(SystemUnderTest.get_cms_id())
        self.vsd.authenticate(SystemUnderTest.get_vsd_credentials())

        USER.report('\n=== Creating VSD gateway resources ===')
        self.gateway = self.vsd.create_gateway(
            name='wbx-' + str(random.randint(1, 0x7fffffff)),
            system_id=str(random.randint(1, 0x7fffffff)),
            personality='NUAGE_210_WBX_32_Q')
        self.gw_port1 = self.vsd.create_gateway_port(self.gateway,
                                                     name='gw-port-1',
                                                     user_mnemonic='gw-port-1',
                                                     vlan_range='0-4095',
                                                     physical_name='gw-port-1',
                                                     port_type='ACCESS')
        self.gw_port2 = self.vsd.create_gateway_port(self.gateway,
                                                     name='gw-port-2',
                                                     user_mnemonic='gw-port-2',
                                                     vlan_range='0-4095',
                                                     physical_name='gw-port-2',
                                                     port_type='ACCESS')
        self.gw_port3 = self.vsd.create_gateway_port(self.gateway,
                                                     name='gw-port-3',
                                                     user_mnemonic='gw-port-3',
                                                     vlan_range='0-4095',
                                                     physical_name='gw-port-3',
                                                     port_type='ACCESS')
        self.gw_port4 = self.vsd.create_gateway_port(self.gateway,
                                                     name='gw-port-4',
                                                     user_mnemonic='gw-port-4',
                                                     vlan_range='0-4095',
                                                     physical_name='gw-port-4',
                                                     port_type='ACCESS')

        # neutron entities
        self.authenticate(SystemUnderTest.get_os_credentials())

        USER.report('=== Creating OpenStack router & networks ===')
        self.router = self.create_router(name='test-router')

        self.networkl3 = self.create_network(name='test-networkl3')
        self.networkl2 = self.create_network(name='test-networkl2')
        self.subnetl3 = self.create_subnet_l3(
            network_id=self.networkl3['id'],
            ip_version=4,
            cidr='10.0.0.0/24')
        self.subnetl2 = self.create_subnet_l2(
            network_id=self.networkl2['id'],
            ip_version=4,
            cidr='10.0.0.0/24')
        self.create_router_interface(router_id=self.router['id'],
                                     subnet_id=self.subnetl3['id'])

        USER.report('=== Creating OpenStack security-group and rules ===')

        # a sg with no representation on vsd that should not influence things
        self.create_security_group_unused(
            name="test-sg-no-representation")

        self.sg = self.create_security_group_used(name="test-sg")
        self.remote_sg = self.create_security_group_remote_used(
            name="test-remote-sg")
        self.sg_rule = self.create_security_group_rule_stateful(
            protocol='icmp', security_group_id=self.sg['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0')

        self.sg_rule_remote_group_id = \
            self.create_security_group_rule_stateful(
                protocol='icmp', security_group_id=self.sg['id'],
                ethertype='IPv4', direction='ingress',
                remote_group_id=self.remote_sg['id'])

        self.sg_hw_port = self.create_security_group_used(
            name="test-sg-hw")
        self.sg_rule_hw = self.create_security_group_rule_stateless(
            protocol='icmp', security_group_id=self.sg_hw_port['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0')
        self.sg_stateless = self.create_security_group_used(
            name="test-sg-stateless", stateful=False)
        self.sg_rule_stateless = self.create_security_group_rule_stateless(
            protocol='icmp', security_group_id=self.sg_stateless['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0')
        # Ports
        USER.report('=== Creating OpenStack ports ===')
        # l3
        self.normal_portl3 = self.create_port(
            self.networkl3, security_groups=[self.sg['id']],
            name='normal_port1')
        self.normal_port2l3 = self.create_port(
            self.networkl3, security_groups=[self.sg['id']],
            name='normal_port2')
        self.normal_port_no_securityl3 = self.create_port(
            self.networkl3, port_security_enabled=False,
            name='normal_port_no_security')
        self.normal_port_no_securityl3_2 = self.create_port(
            self.networkl3, port_security_enabled=False,
            name='normal_port_no_security')
        self.normal_port_stateless_sgl3 = self.create_port(
            self.networkl3, security_groups=[self.sg_stateless['id']],
            name='normal_port_stateless_sg')
        hw_port_args = {
            'name': 'hw-port',
            'security_groups': [self.sg_hw_port['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port1.name,
                     "switch_info": self.gateway.system_id}]
            }}
        self.hw_port_l3 = self.create_port(self.networkl3, **hw_port_args)
        hw_port_args = {
            'name': 'hw-port',
            'security_groups': [self.sg_hw_port['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port2.name,
                     "switch_info": self.gateway.system_id}]
            }}
        self.hw_port_l3_2 = self.create_port(self.networkl3, **hw_port_args)

        # Normal ports l2
        self.normal_portl2 = self.create_port(
            self.networkl2, security_groups=[self.sg['id']],
            name='normal_port1')
        self.normal_port2l2 = self.create_port(
            self.networkl2, security_groups=[self.sg['id']],
            name='normal_port2')
        self.normal_port_no_securityl2 = self.create_port(
            self.networkl2, port_security_enabled=False,
            name='normal_port_no_security')
        self.normal_port_no_securityl2_2 = self.create_port(
            self.networkl2, port_security_enabled=False,
            name='normal_port_no_security')
        self.normal_port_stateless_sgl2 = self.create_port(
            self.networkl2, security_groups=[self.sg_stateless['id']],
            name='normal_port_stateless_sg')

        hw_port_args = {
            'name': 'hw-port',
            'security_groups': [self.sg_hw_port['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port3.name,
                     "switch_info": self.gateway.system_id}]
            }}
        self.hw_port_l2 = self.create_port(self.networkl2, **hw_port_args)
        hw_port_args = {
            'name': 'hw-port',
            'security_groups': [self.sg_hw_port['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port4.name,
                     "switch_info": self.gateway.system_id}]
            }}
        self.hw_port_l2_2 = self.create_port(self.networkl2, **hw_port_args)

        self.pg_for_less_active = True
        self.hardware_port = True

    def teardown(self):
        super(Topology1, self).teardown()

        USER.report('=== Deleting VSD gateway resources ===')
        self.gw_port1.delete()
        self.gw_port2.delete()
        self.gateway.delete()


class SgAuditMockTest(TestBase):
    """Integration tests mocking the neutron client / vsd client getters

    Auditing a real system with validation of audit report and entities_in_sync
    It requires a full OS-VSD setup
    """

    system_under_test = SystemUnderTest(MainArgs('security_group'))

    @classmethod
    def setUpClass(cls):
        super(SgAuditMockTest, cls).setUpClass()
        USER.report('\n===== Start of tests (%s) =====', cls.__name__)

        cls.topology = Topology1()

    @classmethod
    def tearDownClass(cls):
        USER.report('\n===== End of tests (%s) =====', cls.__name__)

        super(SgAuditMockTest, cls).tearDownClass()

        cls.topology.teardown()

    def get_default_expected_in_sync_counter(self):
        return Counter({
            'ingress_acl_entry_templates (PG_FOR_LESS)':
                2 * self.topology.counter['domains']
                if self.topology.pg_for_less_active else 0,
            'egress_acl_entry_templates (PG_FOR_LESS)':
                2 * self.topology.counter['domains']
                if self.topology.pg_for_less_active else 0,
            'egress_acl_entry_templates':
                (self.topology.counter['domains'] *
                 self.topology.counter['sg_rules_ingress']),
            'ingress_acl_entry_templates':
                (self.topology.counter['domains'] *
                 self.topology.counter['sg_rules_egress']),
            'egress_acl_entry_templates (hardware)':
                self.topology.counter['domains']
                if self.topology.hardware_port else 0,
            'policygroups':
                (self.topology.counter['domains'] *
                 self.topology.counter['sgs']),
            'vports': self.topology.counter['ports_sg'],
            'vports (PG_FOR_LESS)':
                self.topology.counter['ports_no_security'],
        })

    @header()
    def test_no_discrepancies(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")

        audit_report, observed_in_sync = self.system_under_test.audit_sg()

        expected_in_sync = self.get_default_expected_in_sync_counter()
        self.assert_counter_equal(expected_in_sync, observed_in_sync)

        # expecting zero discrepancies
        self.assert_audit_report_length(0, audit_report)

    @mock.patch.object(VsdClient, 'get_policy_groups',
                       return_value=[])
    @header()
    def test_missing_policygroups(self, *_):
        """Audit on topology with missing policygroups

        Only hardware block-all rule and PG_for_less are still audited,
        the latter will show discrepancies because of missing policygroups
        """
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        audit_report, observed_in_sync = self.system_under_test.audit_sg()

        # check that we have the correct nr of in sync vsd entities
        # this is the default block-all rule for hardware PG
        expected_in_sync = Counter({
            'egress_acl_entry_templates (hardware)':
                self.topology.counter['domains']
                if self.topology.hardware_port else 0,
        })
        self.assert_counter_equal(expected_in_sync, observed_in_sync)

        # check that we have the correct nr of discrepancies
        expected_discrepancies = Counter({
            'ports_missing_pg_for_less':
                self.topology.counter['ports_no_security'],
            'pgs_missing':
                (self.topology.counter['domains'] *
                 self.topology.counter['sgs'])
        })
        self.assert_audit_report_length(sum(expected_discrepancies.values()),
                                        audit_report)

        # check that all discrepancies are ORPHAN_NEUTRON_ENTITY
        self.assertEqual(
            True, all(discrepancy['discrepancy_type'] ==
                      'ORPHAN_NEUTRON_ENTITY' for discrepancy in audit_report))

        # check that discrepancies have correct entity type
        discrepancy_types_cnt = Counter(
            discrepancy['entity_type'] for discrepancy in audit_report)
        self.assertEqual(expected_discrepancies['ports_missing_pg_for_less'],
                         discrepancy_types_cnt['port'])
        self.assertEqual(expected_discrepancies['pgs_missing'],
                         discrepancy_types_cnt['Security Group'])

    def _mock_get_ports_missing_sgs(self, filters=None, fields=None):
        kwargs = {}
        if filters:
            kwargs = filters
        ports = self.client.list_ports(**kwargs)['ports']
        for port in ports:
            port['security_groups'] = []
        return ports

    @mock.patch.object(NeutronClient, 'get_ports',
                       _mock_get_ports_missing_sgs)
    @header()
    def test_missing_security_groups_for_ports(self, *_):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        audit_report, nr_in_sync = self.system_under_test.audit_sg()
        expected_in_sync = (self.topology.pg_for_less_active * 4 *
                            self.topology.counter['domains'] +
                            self.topology.counter['ports_no_security'])
        self.assert_entities_in_sync(expected_in_sync, nr_in_sync)

        expected_discrepancies = (self.topology.counter['sgs'] *
                                  self.topology.counter['domains'])
        self.assert_audit_report_length(expected_discrepancies, audit_report)
        for discrepancy in audit_report:
            self.assert_equal('ORPHAN_VSD_ENTITY',
                              discrepancy['discrepancy_type'])

    def _mock_get_ports_missing_port(self, filters=None, fields=None):
        # Note that because of mocking, self is the Neutronclient here

        # Leave out removed ports but otherwise execute as normal
        removed_ports = SgAuditMockTest._removed_ports()
        kwargs = {}
        if filters:
            kwargs = filters
        # Ignore fields passed as we do need the name field for testing
        ports = self.client.list_ports(**kwargs)['ports']
        return filter(lambda port: port['id'] not in removed_ports, ports)

    def _get_vports(self, os_port_ids):
        vspk_helper = self.topology.vsd.vspk_helper
        external_id_func = (self.topology.vsd.vspk_helper
                            .get_external_id_filter)

        l2_dom = (vspk_helper.get_default_enterprise().l2_domains
                  .get_first(external_id_func(
                             self.topology.subnetl2['network_id'])))
        l3_dom = (vspk_helper.get_default_enterprise().domains
                  .get_first(external_id_func(self.topology.router['id'])))

        external_id_filters = map(external_id_func, os_port_ids)
        filter_str = ' OR '.join(external_id_filters)
        for domain in [l2_dom, l3_dom]:
            vports = VspkHelper.get_all(parent=domain, filter=filter_str,
                                        fetcher_str="vports")
            for vport in vports:
                yield vport

    @mock.patch.object(NeutronClient, 'get_ports',
                       _mock_get_ports_missing_port)
    @header()
    def test_missing_port(self, *_):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        audit_report, observed_in_sync = self.system_under_test.audit_sg()

        # validate expected in sync
        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_in_sync['vports'] -= 4
        expected_in_sync['vports (PG_FOR_LESS)'] -= 2
        self.assert_counter_equal(expected_in_sync, observed_in_sync)

        # validate discrepancies
        removed_ports = SgAuditMockTest._removed_ports()
        removed_ports_vports = [vport.id for vport in
                                self._get_vports(removed_ports)]

        self.assert_audit_report_length(len(removed_ports), audit_report)

        for discrepancy in audit_report:
            self.assert_equal('ORPHAN_VSD_ENTITY',
                              discrepancy['discrepancy_type'])
            self.assert_equal('Security Group port',
                              discrepancy['entity_type'])
            self.assertIn(discrepancy['vsd_entity'], removed_ports_vports)
            self.assertIsNone(discrepancy['neutron_entity'])
        self.assert_all_different([discrepancy['vsd_entity']
                                   for discrepancy in audit_report])

    @staticmethod
    def _removed_ports():
        return [
            SgAuditMockTest.topology.normal_portl2['id'],
            SgAuditMockTest.topology.normal_portl3['id'],
            SgAuditMockTest.topology.normal_port_no_securityl2['id'],
            SgAuditMockTest.topology.normal_port_no_securityl3['id'],
            SgAuditMockTest.topology.hw_port_l2['id'],
            SgAuditMockTest.topology.hw_port_l3['id']
        ]

    def _mock_get_vports_missing_vport(self, parent=None, vspk_filter=None):
        # Note that since we use mocking, self is the NeutronClient
        removed_ports = SgAuditMockTest._removed_ports()
        external_id_func = (SgAuditMockTest.topology.vsd.vspk_helper
                            .get_external_id_filter)
        external_id_filters = map(external_id_func, removed_ports)
        filter_str = 'NOT (' + ' OR '.join(external_id_filters) + ')'

        if vspk_filter:
            filter_str += ' AND ({})'.format(vspk_filter)

        vports = VspkHelper.get_all(
            parent=parent,
            filter=filter_str,
            fetcher_str="vports")
        return list(vports)

    @mock.patch.object(VsdClient, 'get_vports',
                       new=_mock_get_vports_missing_vport)
    @header()
    def test_missing_vport(self, *_):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        audit_report, observed_in_sync = self.system_under_test.audit_sg()

        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_in_sync['vports'] -= 4
        expected_in_sync['vports (PG_FOR_LESS)'] -= 2
        self.assert_counter_equal(expected_in_sync, observed_in_sync)

        removed_ports = SgAuditMockTest._removed_ports()

        self.assert_audit_report_length(len(removed_ports), audit_report)
        for discrepancy in audit_report:
            self.assert_equal('ORPHAN_NEUTRON_ENTITY',
                              discrepancy['discrepancy_type'])
            self.assert_equal('Security Group port',
                              discrepancy['entity_type'])
            self.assertIn(discrepancy['neutron_entity'], removed_ports)
            self.assertIsNone(discrepancy['vsd_entity'])
        self.assert_all_different([discrepancy['neutron_entity']
                                   for discrepancy in audit_report])

    def _mock_get_security_group_missing_rules(self, sg_id):
        # only keep rules with remote_group being the remote_sg
        sg = self.client.show_security_group(sg_id)['security_group']
        sg['security_group_rules'] = filter(
            lambda r: (r['remote_group_id'] ==
                       SgAuditMockTest.topology.remote_sg['id']),
            sg['security_group_rules'])
        return sg

    @mock.patch.object(NeutronClient, 'get_security_group',
                       new=_mock_get_security_group_missing_rules)
    @header()
    def test_missing_rules_for_security_group(self, *_):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        audit_report, nr_in_sync = self.system_under_test.audit_sg()
        expected_in_sync = (self.topology.counter['ports_sg'] +
                            self.topology.counter['domains'] *
                            (self.topology.counter['sgs'] +
                             self.topology.counter['sg_rules_ingress'] +
                             self.topology.counter['sg_rules_egress']) +
                            self.topology.pg_for_less_active * 4 *
                            self.topology.counter['domains'] +
                            self.topology.hardware_port *
                            self.topology.counter['domains'] +
                            self.topology.counter['ports_no_security'] -
                            self.topology.counter['domains'] *
                            (self.topology.counter['sg_rules_ingress'] +
                             self.topology.counter['sg_rules_egress'] -
                             self.topology.counter['sg_rules_remote']))

        self.assert_entities_in_sync(expected_in_sync, nr_in_sync)

        expected_discrepancies = \
            (self.topology.counter['domains'] *
             (self.topology.counter['sg_rules_ingress'] +
              self.topology.counter['sg_rules_egress'] -
              self.topology.counter['sg_rules_remote']))

        self.assert_audit_report_length(expected_discrepancies, audit_report)
        for discrepancy in audit_report:
            self.assert_equal('ORPHAN_VSD_ENTITY',
                              discrepancy['discrepancy_type'])

    @mock.patch.object(VsdClient, 'get_ingress_acl_entries',
                       return_value=[])
    @mock.patch.object(VsdClient, 'get_egress_acl_entries',
                       return_value=[])
    @mock.patch.object(VsdClient, 'get_egress_acl_entries_by_acl',
                       return_value=[])
    @header()
    def test_missing_acl_entries(self, *_):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        audit_report, nr_in_sync = self.system_under_test.audit_sg()
        expected_in_sync = (self.topology.counter['ports_sg'] +
                            self.topology.counter['domains'] *
                            self.topology.counter['sgs'] +
                            self.topology.counter['ports_no_security'])
        self.assert_entities_in_sync(expected_in_sync, nr_in_sync)

        expected_discrepancies = \
            (self.topology.counter['domains'] *
             (self.topology.counter['sg_rules_ingress'] +
              self.topology.counter['sg_rules_egress']) +
             self.topology.pg_for_less_active * 4 *
             self.topology.counter['domains'] +
             self.topology.hardware_port * self.topology.counter['domains'])
        self.assert_audit_report_length(expected_discrepancies, audit_report)
        mismatch = 0
        orphan = 0
        for discrepancy in audit_report:
            if discrepancy['discrepancy_type'] == 'ENTITY_MISMATCH':
                mismatch += 1
            elif discrepancy['discrepancy_type'] == 'ORPHAN_NEUTRON_ENTITY':
                orphan += 1
            else:
                self.fail("Discrepancy type {} unexpected.".format(
                    discrepancy['discrepancy_type']))
        expected_mismatches = (self.topology.pg_for_less_active * 4 *
                               self.topology.counter['domains'])
        self.assert_equal(expected_mismatches, mismatch,
                          'Exactly {} entity mismatches expected, found {}')
        expected_orphans = (self.topology.counter['domains'] *
                            (self.topology.counter['sg_rules_ingress'] +
                             self.topology.counter['sg_rules_egress']) +
                            self.topology.hardware_port *
                            self.topology.counter['domains'])
        self.assert_equal(expected_orphans, orphan,
                          'Exactly {} neutron orphans expected, found {}')

    def mock_get_security_group_changed_sg(self, sg_id):
        sg = self.client.show_security_group(sg_id)['security_group']
        sg['name'] = ''
        return sg

    @mock.patch.object(NeutronClient, 'get_security_group',
                       new=mock_get_security_group_changed_sg)
    @header()
    def test_mismatch_security_group(self, *_):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        audit_report, nr_in_sync = self.system_under_test.audit_sg()

        # Expected: pg for less + port with no port security
        expected_in_sync = (self.topology.pg_for_less_active * 4 *
                            self.topology.counter['domains'] +
                            self.topology.hardware_port *
                            self.topology.counter['domains'] +
                            self.topology.counter['ports_no_security'])
        self.assert_entities_in_sync(expected_in_sync, nr_in_sync)

        expected_discrepancies = (self.topology.counter['sgs'] *
                                  self.topology.counter['domains'])
        self.assert_audit_report_length(expected_discrepancies, audit_report)
        for discrepancy in audit_report:
            self.assert_equal('ENTITY_MISMATCH',
                              discrepancy['discrepancy_type'])

    def mock_get_security_group_changed_sg_rule(self, sg_id):
        sg = self.client.show_security_group(sg_id)['security_group']
        for sg_rule in sg['security_group_rules']:
            sg_rule['port_range_min'] = 1
            sg_rule['port_range_max'] = 1
            if not sg_rule['protocol']:
                sg_rule['protocol'] = 'tcp'
        return sg

    @mock.patch.object(NeutronClient, 'get_security_group',
                       new=mock_get_security_group_changed_sg_rule)
    @header()
    def test_mismatch_sg_rule(self, *_):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        audit_report, nr_in_sync = self.system_under_test.audit_sg()
        INFO.pprint(audit_report)

        expected_in_sync = (self.topology.counter['ports_sg'] +
                            self.topology.counter['domains'] *
                            self.topology.counter['sgs'] +
                            self.topology.pg_for_less_active * 4 *
                            self.topology.counter['domains'] +
                            self.topology.hardware_port *
                            self.topology.counter['domains'] +
                            self.topology.counter['ports_no_security'])
        self.assert_entities_in_sync(expected_in_sync, nr_in_sync)

        expected_discrepancies = \
            (self.topology.counter['domains'] *
             (self.topology.counter['sg_rules_ingress'] +
              self.topology.counter['sg_rules_egress']))
        self.assert_audit_report_length(expected_discrepancies, audit_report)
        for discrepancy in audit_report:
            self.assert_equal('ENTITY_MISMATCH',
                              discrepancy['discrepancy_type'])

    @header()
    def test_pg_for_less_too_many_acl_entries(self):
        """Audit with duplicated pg for less entries"""
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        original_fetcher = VsdClient.get_ingress_acl_entries

        pg_for_less_ids = [
            pg.id for domain in self.topology.vsd.get_domains()
            for pg in self.topology.vsd.get_policy_groups(
                domain, vspk_filter="name BEGINSWITH 'PG_FOR_LESS_SECURITY'")]

        def mock_get_ingress_acl_entries(*args, **kwargs):
            original_entries = list(original_fetcher(*args, **kwargs))
            pg_for_less_entries = [entry for entry in original_entries
                                   if entry.location_id in pg_for_less_ids]
            return original_entries + pg_for_less_entries

        with mock.patch.object(
                VsdClient, 'get_ingress_acl_entries',
                new=mock_get_ingress_acl_entries):
            # audit
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            INFO.pprint(audit_report)

            # discrepancy validation
            # there are 2 orphans per domain, an IPv4 and IPv6 ingress rule
            expected_discrepancies = self.topology.counter['domains'] * 2 \
                if self.topology.pg_for_less_active else 0
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            for entry in audit_report:
                self.assertEqual('ORPHAN_VSD_ENTITY',
                                 entry['discrepancy_type'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

    @header()
    def test_pg_for_less_invalid_rules_action(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")

        original_fetcher = VsdClient.get_ingress_acl_entries

        pg_for_less_ids = [
            pg.id for domain in self.topology.vsd.get_domains()
            for pg in self.topology.vsd.get_policy_groups(
                domain, vspk_filter="name BEGINSWITH 'PG_FOR_LESS_SECURITY'")]

        def mock_get_ingress_acl_entries_bad_action(*args, **kwargs):
            for entry in original_fetcher(*args, **kwargs):
                if entry.location_id in pg_for_less_ids:
                    entry.action = ''  # Used to be FORWARD
                yield entry

        with mock.patch.object(
                VsdClient, 'get_ingress_acl_entries',
                new=mock_get_ingress_acl_entries_bad_action):
            # audit
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            INFO.pprint(audit_report)

            # discrepancy validation
            # there are 2 mismatches per domain, an IPv4 and IPv6 ingress rule
            expected_discrepancies = self.topology.counter['domains'] * 2 \
                if self.topology.pg_for_less_active else 0
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            for entry in audit_report:
                self.assertEqual('ENTITY_MISMATCH',
                                 entry['discrepancy_type'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

    @header()
    def test_pg_for_less_invalid_rules_ethertype(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")

        original_fetcher = VsdClient.get_ingress_acl_entries

        pg_for_less_ids = [
            pg.id for domain in self.topology.vsd.get_domains()
            for pg in self.topology.vsd.get_policy_groups(
                domain, vspk_filter="name BEGINSWITH 'PG_FOR_LESS_SECURITY'")]

        def mock_get_ingress_acl_entries_bad_ether_type(*args, **kwargs):
            for entry in original_fetcher(*args, **kwargs):
                if entry.location_id in pg_for_less_ids:
                    entry.ether_type = ''  # Used to represent IPv4/IPv6
                yield entry

        with mock.patch.object(
                VsdClient, 'get_ingress_acl_entries',
                new=mock_get_ingress_acl_entries_bad_ether_type):
            # audit
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            INFO.pprint(audit_report)

            # discrepancy validation
            # there are 4 mismatches per domain, invalid rule for IPv4 and IPv6
            # and detection of missing entry for IPv4 and IPv6
            expected_discrepancies = self.topology.counter['domains'] * 4 \
                if self.topology.pg_for_less_active else 0
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            for entry in audit_report:
                self.assertEqual('ENTITY_MISMATCH',
                                 entry['discrepancy_type'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

    @header()
    def test_hardware_block_all_acl_missing(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        original_fetcher = VsdClient.get_egress_acl_templates_by_external_id

        def mock_fetcher_missing_hardware_acl(*args, **kwargs):
            return ([] if kwargs.get('external_id', '').startswith('hw:')
                    else original_fetcher(*args, **kwargs))

        with mock.patch.object(
                VsdClient, 'get_egress_acl_templates_by_external_id',
                new=mock_fetcher_missing_hardware_acl):
            # audit
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            INFO.pprint(audit_report)

            # discrepancy validation
            # There is one orphans per domain since each domain has one
            # block-all acl for hardware vports
            expected_discrepancies = (self.topology.counter['domains']
                                      if self.topology.hardware_port else 0)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            for entry in audit_report:
                self.assertEqual('ORPHAN_NEUTRON_ENTITY',
                                 entry['discrepancy_type'])
                self.assertEqual('Missing hardware block-all ACL.',
                                 entry['discrepancy_details'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['egress_acl_entry_templates (hardware)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

    @header()
    def test_hardware_block_all_acl_too_many_rules(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        original_fetcher = VsdClient.get_egress_acl_entries_by_acl

        def mock_fetcher_double_acl_entries(*args, **kwargs):
            # args[0] is self, args[1] is acl
            entries = list(original_fetcher(*args[1:], **kwargs))
            return (entries * 2 if args[1].external_id.startswith('hw:')
                    else entries)

        with mock.patch.object(
                VsdClient, 'get_egress_acl_entries_by_acl',
                new=mock_fetcher_double_acl_entries):
            # audit
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            INFO.pprint(audit_report)

            # discrepancy validation
            # Normally we have one entry per domain, since we doubled the
            # entries there is now one excess entry per domain
            expected_discrepancies = (self.topology.counter['domains']
                                      if self.topology.hardware_port else 0)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            for entry in audit_report:
                self.assertEqual('ORPHAN_VSD_ENTITY',
                                 entry['discrepancy_type'])
                self.assertEqual('Hardware block-all ACL '
                                 'has more than one rule',
                                 entry['discrepancy_details'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

    @header()
    def test_hardware_block_all_acl_invalid_rules(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        original_fetcher = VsdClient.get_egress_acl_entries_by_acl

        def mock_fetcher_invalid_acl_entries(*args, **kwargs):
            # args[0] is self, args[1] is acl
            entries = list(original_fetcher(*args[1:], **kwargs))
            for entry in entries:
                entry.action = random.choice(['', 'FORWARD', 'drop', 'bar'])
            return entries

        with mock.patch.object(
                VsdClient, 'get_egress_acl_entries_by_acl',
                new=mock_fetcher_invalid_acl_entries):
            # audit
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            INFO.pprint(audit_report)

            # discrepancy validation
            # There is one mismatch per domain since each domain has one
            # block-all acl with one rule for hardware vports
            expected_discrepancies = (self.topology.counter['domains']
                                      if self.topology.hardware_port else 0)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            for entry in audit_report:
                self.assertEqual('ENTITY_MISMATCH',
                                 entry['discrepancy_type'])
                self.assertEqual('Invalid rule for hardware block-all acl',
                                 entry['discrepancy_details'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['egress_acl_entry_templates (hardware)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

    @header()
    def test_port_security_mismatch(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        original_getter = NeutronClient.get_ports

        def mock_get_ports_missing_port_security(*args, **kwargs):
            ports = original_getter(*args, **kwargs)
            port = next((port for port in ports
                         if port.get('id') ==
                         self.topology.normal_portl3['id']), None)
            if port:
                self.assertIs(True, port.get('port_security_enabled'))
                port['port_security_enabled'] = False
                port['security_groups'] = []
            return ports

        with mock.patch.object(
                NeutronClient, 'get_ports',
                new=mock_get_ports_missing_port_security):
            # audit
            audit_report, observed_in_sync = self.system_under_test.audit_sg()
            INFO.pprint(audit_report)

            # discrepancy validation
            # The neutron port is not linked anymore with the vPort,
            # so we have one neutron orphan and one VSD orphan
            self.assert_audit_report_length(2, audit_report)
            self.assert_equal(
                expected={'ORPHAN_VSD_ENTITY', 'ORPHAN_NEUTRON_ENTITY'},
                observed={discrepancy['discrepancy_type']
                          for discrepancy in audit_report})
            neutron_discrepancy = next(
                discrepancy for discrepancy in audit_report
                if discrepancy['discrepancy_type'] == 'ORPHAN_NEUTRON_ENTITY')
            self.assert_equal(expected=self.topology.normal_portl3['id'],
                              observed=neutron_discrepancy['neutron_entity'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['vports'] -= 1
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

    @header()
    @mock.patch.object(VsdClient, 'get_l2domain',
                       return_value=None)
    @mock.patch.object(VsdClient, 'get_l3domain',
                       return_value=None)
    def test_missing_domains(self, *_):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        # audit
        audit_report, observed_in_sync = self.system_under_test.audit_sg()
        INFO.pprint(audit_report)

        # Nothing is in sync, we cut of early in case of missing domain
        self.assert_counter_equal(Counter(), observed_in_sync)

        # A discrepancy for each domain
        self.assertEqual(self.topology.counter['domains'], len(audit_report))

        for discrepancy in audit_report:
            self.assert_equal('ORPHAN_NEUTRON_ENTITY',
                              discrepancy['discrepancy_type'])
            self.assertIsNone(discrepancy['vsd_entity'])
            self.assertIn(discrepancy['neutron_entity'],
                          [self.topology.router['id'],
                           self.topology.subnetl2['id']])
            if discrepancy['neutron_entity'] == self.topology.router['id']:
                self.assert_equal(discrepancy['discrepancy_details'],
                                  'router has no l3-domain')
            else:
                self.assert_equal(discrepancy['discrepancy_details'],
                                  'l2-subnet has no l2-domain')
