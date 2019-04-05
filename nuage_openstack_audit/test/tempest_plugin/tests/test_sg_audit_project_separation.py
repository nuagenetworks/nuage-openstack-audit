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
from nuage_openstack_audit.test.tempest_plugin.tests.utils.vsd_test_helper \
    import VSDTestHelper
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.vsdclient.common.vspk_helper import VspkHelper

# run me using:
# python -m testtools.run \
#   nuage_openstack_audit/test/test_sg_audit_project_separation.py


WARN = Reporter('WARN')
USER = Reporter('USER')
INFO = Reporter('INFO')


class TopologyProjectSeperation(NeutronTopology):

    def __init__(self):
        super(TopologyProjectSeperation, self).__init__()
        self.keystone = KeystoneClient()

        # vsd entities
        self.vsd = VSDTestHelper(SystemUnderTest.get_cms_id())
        self.vsd.authenticate(SystemUnderTest.get_vsd_credentials())
        USER.report('\n=== Creating VSD gateway resources ===')
        self.gateway = self.vsd.create_gateway(
            name='wbx-' + str(random.randint(1, 0x7fffffff)),
            system_id=str(random.randint(1, 0x7fffffff)),
            personality='NUAGE_210_WBX_32_Q')
        self.gw_port1_project1 = self.vsd.create_gateway_port(
            self.gateway, name='gw-port-1-p1',
            user_mnemonic='gw-port-1',
            vlan_range='0-4095',
            physical_name='gw-port-1-p1',
            port_type='ACCESS')
        self.gw_port2_project1 = self.vsd.create_gateway_port(
            self.gateway, name='gw-port-2-p1',
            user_mnemonic='gw-port-2-p1',
            vlan_range='0-4095',
            physical_name='gw-port-2-p1',
            port_type='ACCESS')
        self.gw_port3_project1 = self.vsd.create_gateway_port(
            self.gateway, name='gw-port-3-p1',
            user_mnemonic='gw-port-3-p1',
            vlan_range='0-4095',
            physical_name='gw-port-3-p1',
            port_type='ACCESS')
        self.gw_port4_project1 = self.vsd.create_gateway_port(
            self.gateway, name='gw-port-4-p1',
            user_mnemonic='gw-port-4-p1',
            vlan_range='0-4095',
            physical_name='gw-port-4-p1',
            port_type='ACCESS')
        self.gw_port1_project2 = self.vsd.create_gateway_port(
            self.gateway, name='gw-port-1-p2',
            user_mnemonic='gw-port-1-p2',
            vlan_range='0-4095',
            physical_name='gw-port-1-p2',
            port_type='ACCESS')
        self.gw_port2_project2 = self.vsd.create_gateway_port(
            self.gateway, name='gw-port-2-p2',
            user_mnemonic='gw-port-2-p2',
            vlan_range='0-4095',
            physical_name='gw-port-2-p2',
            port_type='ACCESS')
        self.gw_port3_project2 = self.vsd.create_gateway_port(
            self.gateway, name='gw-port-3-p2',
            user_mnemonic='gw-port-3-p2',
            vlan_range='0-4095',
            physical_name='gw-port-3-p2',
            port_type='ACCESS')
        self.gw_port4_project2 = self.vsd.create_gateway_port(
            self.gateway, name='gw-port-4-p2',
            user_mnemonic='gw-port-4-p2',
            vlan_range='0-4095',
            physical_name='gw-port-4-p2',
            port_type='ACCESS')

        # neutron entities
        os_credentials = SystemUnderTest.get_os_credentials()
        self.authenticate(os_credentials)

        # Create two projects
        self.project1 = self.keystone.client.projects.create(
            'test-project1', 'default')
        self.project2 = self.keystone.client.projects.create(
            'test-project2', 'default')

        # Double everything for each project

        USER.report('=== Creating OpenStack router & networks ===')
        self.router_project1 = self.create_router(
            name='test-router-project1', project_id=self.project1.id)
        self.router_project2 = self.create_router(
            name='test-router-project2', project_id=self.project2.id)

        self.networkl3_project1 = self.create_network(
            name='test-networkl3-project1', project_id=self.project1.id)
        self.networkl3_project2 = self.create_network(
            name='test-networkl3-project2', project_id=self.project2.id)
        self.networkl2_project1 = self.create_network(
            name='test-networkl2-project1', project_id=self.project1.id)
        self.networkl2_project2 = self.create_network(
            name='test-networkl2-project2', project_id=self.project2.id)
        self.subnetl3_project1 = self.create_subnet_l3(
            network_id=self.networkl3_project1['id'],
            ip_version=4,
            cidr='10.0.0.0/24', project_id=self.project1.id)
        self.subnetl3_project2 = self.create_subnet_l3(
            network_id=self.networkl3_project2['id'],
            ip_version=4,
            cidr='10.0.0.0/24', project_id=self.project2.id)
        self.subnetl2_project1 = self.create_subnet_l2(
            network_id=self.networkl2_project1['id'],
            ip_version=4,
            cidr='10.0.0.0/24', project_id=self.project1.id)
        self.subnetl2_project2 = self.create_subnet_l2(
            network_id=self.networkl2_project2['id'],
            ip_version=4,
            cidr='10.0.0.0/24', project_id=self.project2.id)
        self.create_router_interface(router_id=self.router_project1['id'],
                                     subnet_id=self.subnetl3_project1[
                                         'id'],
                                     project_id=self.project1.id)
        self.create_router_interface(router_id=self.router_project2['id'],
                                     subnet_id=self.subnetl3_project2[
                                         'id'],
                                     project_id=self.project2.id)

        USER.report('=== Creating OpenStack security-group and rules ===')

        # a sg with no representation on vsd that should not influence things
        self.create_security_group_unused(
            name="test-sg-no-representation-project1",
            project_id=self.project1.id)
        self.create_security_group_unused(
            name="test-sg-no-representation-project2",
            project_id=self.project2.id)

        self.sg_project1 = self.create_security_group_used(
            name="test-sg-project1", project_id=self.project1.id)
        self.sg_project2 = self.create_security_group_used(
            name="test-sg-project2", project_id=self.project2.id)

        self.remote_sg_project1 = self.create_security_group_remote_used(
            name="test-remote-sg-project1", project_id=self.project1.id)
        self.remote_sg_project2 = self.create_security_group_remote_used(
            name="test-remote-sg-project2", project_id=self.project2.id)

        self.sg_rule_project1 = self.create_security_group_rule_stateful(
            protocol='icmp', security_group_id=self.sg_project1['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0', project_id=self.project1.id)
        self.sg_rule_project2 = self.create_security_group_rule_stateful(
            protocol='icmp', security_group_id=self.sg_project2['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0', project_id=self.project1.id)

        self.sg_rule_remote_group_id_project1 = \
            self.create_security_group_rule_stateful(
                protocol='icmp', security_group_id=self.sg_project1['id'],
                ethertype='IPv4', direction='ingress',
                remote_group_id=self.remote_sg_project1['id'],
                project_id=self.project1.id)
        self.sg_rule_remote_group_id_project2 = \
            self.create_security_group_rule_stateful(
                protocol='icmp', security_group_id=self.sg_project2['id'],
                ethertype='IPv4', direction='ingress',
                remote_group_id=self.remote_sg_project2['id'],
                project_id=self.project2.id)

        self.sg_hw_port_project1 = self.create_security_group_used(
            name="test-sg-hw-project1", project_id=self.project1.id)
        self.sg_hw_port_project2 = self.create_security_group_used(
            name="test-sg-hw-project2", project_id=self.project2.id)

        self.sg_rule_hw_project1 = self.create_security_group_rule_stateless(
            protocol='icmp',
            security_group_id=self.sg_hw_port_project1['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0', project_id=self.project1.id)
        self.sg_rule_hw_project2 = self.create_security_group_rule_stateless(
            protocol='icmp',
            security_group_id=self.sg_hw_port_project2['id'],
            ethertype='IPv4', direction='ingress',
            remote_ip_prefix='0.0.0.0/0', project_id=self.project2.id)

        self.sg_stateless_project1 = self.create_security_group_used(
            name="test-sg-stateless-project1", stateful=False,
            project_id=self.project1.id)
        self.sg_stateless_project2 = self.create_security_group_used(
            name="test-sg-stateless-project2", stateful=False,
            project_id=self.project2.id)

        self.sg_rule_stateless_project1 = \
            self.create_security_group_rule_stateless(
                protocol='icmp',
                security_group_id=self.sg_stateless_project1['id'],
                ethertype='IPv4', direction='ingress',
                remote_ip_prefix='0.0.0.0/0', project_id=self.project1.id)
        self.sg_rule_stateless_project2 = \
            self.create_security_group_rule_stateless(
                protocol='icmp',
                security_group_id=self.sg_stateless_project2['id'],
                ethertype='IPv4', direction='ingress',
                remote_ip_prefix='0.0.0.0/0', project_id=self.project2.id)

        # Ports
        USER.report('=== Creating OpenStack ports ===')
        # l3
        self.normal_portl3_project1 = self.create_port(
            self.networkl3_project1,
            security_groups=[self.sg_project1['id']],
            name='normal_port1_project1', project_id=self.project1.id)
        self.normal_portl3_project2 = self.create_port(
            self.networkl3_project2,
            security_groups=[self.sg_project2['id']],
            name='normal_port1_project2', project_id=self.project2.id)

        self.normal_port2l3_project1 = self.create_port(
            self.networkl3_project1,
            security_groups=[self.sg_project1['id']],
            name='normal_port2-project1', project_id=self.project1.id)
        self.normal_port2l3_project2 = self.create_port(
            self.networkl3_project2,
            security_groups=[self.sg_project2['id']],
            name='normal_port2-project2', project_id=self.project2.id)

        self.normal_port_no_securityl3_project1 = self.create_port(
            self.networkl3_project1, port_security_enabled=False,
            name='normal_port_no_security-project1',
            project_id=self.project1.id)
        self.normal_port_no_securityl3_project2 = self.create_port(
            self.networkl3_project2, port_security_enabled=False,
            name='normal_port_no_security-project2',
            project_id=self.project2.id)

        self.normal_port_no_securityl3_2_project1 = self.create_port(
            self.networkl3_project1, port_security_enabled=False,
            name='normal_port_no_security_project1',
            project_id=self.project1.id)
        self.normal_port_no_securityl3_2_project2 = self.create_port(
            self.networkl3_project2, port_security_enabled=False,
            name='normal_port_no_security_project2',
            project_id=self.project2.id)

        self.normal_port_stateless_sgl3_project1 = self.create_port(
            self.networkl3_project1,
            security_groups=[self.sg_stateless_project1['id']],
            name='normal_port_stateless_sg_project1',
            project_id=self.project1.id)
        self.normal_port_stateless_sgl3_project2 = self.create_port(
            self.networkl3_project2,
            security_groups=[self.sg_stateless_project2['id']],
            name='normal_port_stateless_sg_project2',
            project_id=self.project2.id)

        hw_port_args = {
            'name': 'hw-port-l3-project1',
            'security_groups': [self.sg_hw_port_project1['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port1_project1.name,
                     "switch_info": self.gateway.system_id}]
            },
            'project_id': self.project1.id
        }
        self.hw_port_l3_project1 = self.create_port(
            self.networkl3_project1,
            **hw_port_args)
        hw_port_args = {
            'name': 'hw-port-l3-project2',
            'security_groups': [self.sg_hw_port_project2['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port1_project2.name,
                     "switch_info": self.gateway.system_id}]
            },
            'project_id': self.project2.id

        }
        self.hw_port_l3_project2 = self.create_port(
            self.networkl3_project2,
            **hw_port_args)

        hw_port_args = {
            'name': 'hw-port-l3-2-project1',
            'security_groups': [self.sg_hw_port_project1['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port2_project1.name,
                     "switch_info": self.gateway.system_id}]
            },
            'project_id': self.project1.id
        }
        self.hw_port_l3_2_project1 = self.create_port(
            self.networkl3_project1,
            **hw_port_args)
        hw_port_args = {
            'name': 'hw-port-l3-2-project2',
            'security_groups': [self.sg_hw_port_project2['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port2_project2.name,
                     "switch_info": self.gateway.system_id}]
            },
            'project_id': self.project2.id
        }
        self.hw_port_l3_2_project2 = self.create_port(
            self.networkl3_project2,
            **hw_port_args)

        # Normal ports l2
        self.normal_portl2_project1 = self.create_port(
            self.networkl2_project1,
            security_groups=[self.sg_project1['id']],
            name='normal_port1_project1', project_id=self.project1.id)
        self.normal_portl2_project2 = self.create_port(
            self.networkl2_project2,
            security_groups=[self.sg_project2['id']],
            name='normal_port1_project2', project_id=self.project2.id)

        self.normal_port2l2_project1 = self.create_port(
            self.networkl2_project1,
            security_groups=[self.sg_project1['id']],
            name='normal_port2_project1', project_id=self.project1.id)
        self.normal_port2l2_project2 = self.create_port(
            self.networkl2_project2,
            security_groups=[self.sg_project2['id']],
            name='normal_port2_project2', project_id=self.project2.id)

        self.normal_port_no_securityl2_project1 = self.create_port(
            self.networkl2_project1, port_security_enabled=False,
            name='normal_port_no_security_project1',
            project_id=self.project1.id)
        self.normal_port_no_securityl2_project2 = self.create_port(
            self.networkl2_project2, port_security_enabled=False,
            name='normal_port_no_security_project2',
            project_id=self.project2.id)

        self.normal_port_no_securityl2_2_project1 = self.create_port(
            self.networkl2_project1, port_security_enabled=False,
            name='normal_port_no_security_project1',
            project_id=self.project1.id)
        self.normal_port_no_securityl2_2_project2 = self.create_port(
            self.networkl2_project2, port_security_enabled=False,
            name='normal_port_no_security_project2',
            project_id=self.project2.id)

        self.normal_port_stateless_sgl2_project1 = self.create_port(
            self.networkl2_project1,
            security_groups=[self.sg_stateless_project1['id']],
            name='normal_port_stateless_sg_project1',
            project_id=self.project1.id)
        self.normal_port_stateless_sgl2_project2 = self.create_port(
            self.networkl2_project2,
            security_groups=[self.sg_stateless_project2['id']],
            name='normal_port_stateless_sg_project2',
            project_id=self.project2.id)

        hw_port_args = {
            'name': 'hw-port-l2-project1',
            'security_groups': [self.sg_hw_port_project1['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port3_project1.name,
                     "switch_info": self.gateway.system_id}]
            },
            'project_id': self.project1.id}
        self.hw_port_l2_project1 = self.create_port(
            self.networkl2_project1,
            **hw_port_args)
        hw_port_args = {
            'name': 'hw-port-l2-project2',
            'security_groups': [self.sg_hw_port_project2['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port3_project2.name,
                     "switch_info": self.gateway.system_id}]
            },
            'project_id': self.project2.id}

        self.hw_port_l2_project2 = self.create_port(
            self.networkl2_project2,
            **hw_port_args)

        hw_port_args = {
            'name': 'hw-port-l2-2-project1',
            'security_groups': [self.sg_hw_port_project1['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port4_project1.name,
                     "switch_info": self.gateway.system_id}]
            },
            'project_id': self.project1.id}
        self.hw_port_l2_2_project1 = self.create_port(
            self.networkl2_project1,
            **hw_port_args)
        hw_port_args = {
            'name': 'hw-port-l2-2-project2',
            'security_groups': [self.sg_hw_port_project2['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port4_project2.name,
                     "switch_info": self.gateway.system_id}]
            },
            'project_id': self.project2.id}

        self.hw_port_l2_2_project2 = self.create_port(
            self.networkl2_project2,
            **hw_port_args)
        self.pg_for_less_active = True
        self.hardware_port = True

    def teardown(self):
        super(TopologyProjectSeperation, self).teardown()

        USER.report('=== Deleting VSD gateway resources ===')
        self.gw_port1_project1.delete()
        self.gw_port1_project2.delete()
        self.gw_port2_project1.delete()
        self.gw_port2_project2.delete()
        self.gateway.delete()
        USER.report('=== Deleting Keystone resources ===')
        self.keystone.client.projects.delete(self.project1.id)
        self.keystone.client.projects.delete(self.project2.id)

    def authenticate(self, credentials, db_access=False):
        super(TopologyProjectSeperation, self).authenticate(credentials,
                                                            db_access)
        self.keystone.authenticate(credentials)


class SgMockProjectSepTest(TestBase):
    """Integration tests mocking the neutron client / vsd client getters

    Auditing a real system with validation of audit report and entities_in_sync
    It requires a full OS-VSD setup
    """

    @classmethod
    def setUpClass(cls):
        super(SgMockProjectSepTest, cls).setUpClass()
        USER.report('\n===== Start of tests (%s) =====', cls.__name__)

        cls.topology = TopologyProjectSeperation()
        cls.sut = SystemUnderTest(MainArgs('security_group'))
        cls.sut_project_1 = SystemUnderTest(MainArgs(
            'security_group', project=cls.topology.project1.id))
        cls.sut_project_2 = SystemUnderTest(MainArgs(
            'security_group', project=cls.topology.project2.id))

    @classmethod
    def tearDownClass(cls):
        USER.report('\n===== End of tests (%s) =====', cls.__name__)

        super(SgMockProjectSepTest, cls).tearDownClass()
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
                 (self.topology.counter['sg_rules_ingress'] / 2)),
            'ingress_acl_entry_templates':
                (self.topology.counter['domains'] *
                 (self.topology.counter['sg_rules_egress'] / 2)),
            'egress_acl_entry_templates (hardware)':
                self.topology.counter['domains']
                if self.topology.hardware_port else 0,
            'policygroups':
                (self.topology.counter['domains'] *
                 (self.topology.counter['sgs'] / 2)),
            'vports': self.topology.counter['ports_sg'],
            'vports (PG_FOR_LESS)':
                self.topology.counter['ports_no_security'],
        })

    def get_per_project_expected_in_sync_counter(self):
        # Divide by two because there are two projects
        counter = self.get_default_expected_in_sync_counter()
        for key in counter:
            counter[key] /= 2
        return counter

    @header()
    def test_no_discrepancies(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")

        # Audit with project 1
        audit_report, observed_in_sync = self.sut_project_1.audit_sg()
        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        self.assert_counter_equal(expected_in_sync, observed_in_sync)
        self.assert_audit_report_length(0, audit_report)

        # Audit with project 2
        audit_report, observed_in_sync = self.sut_project_2.audit_sg()
        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        self.assert_counter_equal(expected_in_sync, observed_in_sync)
        self.assert_audit_report_length(0, audit_report)

        # Audit without project id
        audit_report, observed_in_sync = self.sut.audit_sg()
        expected_in_sync = self.get_default_expected_in_sync_counter()
        self.assert_counter_equal(expected_in_sync, observed_in_sync)
        # expecting zero discrepancies
        self.assert_audit_report_length(0, audit_report)

    @header()
    def test_no_discrepancies_project_user(self):
        keystone_client = self.topology.keystone.client
        project1 = self.topology.project1
        os_credentials = self.sut.get_os_credentials()
        user1 = keystone_client.users.create(
            'user-project1', project=project1,
            password=os_credentials.password)
        os_credentials.project_name = project1.name
        os_credentials.username = user1.name

        role = next(role for role in keystone_client.roles.list() if
                    role.name == 'Member')
        keystone_client.roles.grant(role, user=user1, project=project1)
        sut_user1 = SystemUnderTest(MainArgs(
            'security_group', project=project1.id))
        sut_user1.neutron = sut_user1.get_neutron_client(os_credentials,
                                                         project1.id)
        audit_report, observed_in_sync = self.sut_project_1.audit_sg()
        # Delete before assertions as it is not part of normal cleanup
        keystone_client.users.delete(user1.id)
        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        self.assert_counter_equal(expected_in_sync, observed_in_sync)
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
        audit_report, observed_in_sync = self.sut.audit_sg()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

        # check that we have the correct nr of in sync vsd entities
        # this is the default block-all rule for hardware PG
        expected_in_sync = Counter({
            'egress_acl_entry_templates (hardware)':
                self.get_default_expected_in_sync_counter()[
                    'egress_acl_entry_templates (hardware)']
        })
        self.assert_counter_equal(expected_in_sync, observed_in_sync)
        expected_in_sync = Counter({
            'egress_acl_entry_templates (hardware)':
                self.get_per_project_expected_in_sync_counter()[
                    'egress_acl_entry_templates (hardware)']
        })
        self.assert_counter_equal(expected_in_sync, observed_in_sync1)
        self.assert_counter_equal(expected_in_sync, observed_in_sync2)

        # check that we have the correct nr of discrepancies
        # number of ports missing is the number of ports without security
        # number of pgs missing is the number of domains * number of SG / 2
        # Divided by two because only half of SG is for a domain as we have
        # two tenants.
        expected_discrepancies = Counter({
            'ports_missing_pg_for_less':
                self.topology.counter['ports_no_security'],
            'pgs_missing':
                self.get_default_expected_in_sync_counter()['policygroups']
        })
        self.assert_audit_report_length(sum(expected_discrepancies.values()),
                                        audit_report)
        self.assert_audit_report_length(
            sum(expected_discrepancies.values()) / 2, audit_report1)
        self.assert_audit_report_length(
            sum(expected_discrepancies.values()) / 2, audit_report1)

        # check that all discrepancies are ORPHAN_NEUTRON_ENTITY
        self.assertEqual(
            True, all(discrepancy['discrepancy_type'] ==
                      'ORPHAN_NEUTRON_ENTITY' for discrepancy in audit_report))
        self.assertEqual(
            True, all(discrepancy['discrepancy_type'] ==
                      'ORPHAN_NEUTRON_ENTITY' for discrepancy
                      in audit_report1))
        self.assertEqual(
            True, all(discrepancy['discrepancy_type'] ==
                      'ORPHAN_NEUTRON_ENTITY' for discrepancy
                      in audit_report1))

        # check that discrepancies have correct entity type
        discrepancy_types_cnt = Counter(
            discrepancy['entity_type'] for discrepancy in audit_report)
        discrepancy_types_cnt1 = Counter(
            discrepancy['entity_type'] for discrepancy in audit_report1)
        discrepancy_types_cnt2 = Counter(
            discrepancy['entity_type'] for discrepancy in audit_report2)
        self.assertEqual(expected_discrepancies['ports_missing_pg_for_less'],
                         discrepancy_types_cnt['port'])
        self.assertEqual(
            expected_discrepancies['ports_missing_pg_for_less'] / 2,
            discrepancy_types_cnt1['port'])
        self.assertEqual(
            expected_discrepancies['ports_missing_pg_for_less'] / 2,
            discrepancy_types_cnt2['port'])
        self.assertEqual(expected_discrepancies['pgs_missing'],
                         discrepancy_types_cnt['Security Group'])
        self.assertEqual(expected_discrepancies['pgs_missing'] / 2,
                         discrepancy_types_cnt1['Security Group'])
        self.assertEqual(expected_discrepancies['pgs_missing'] / 2,
                         discrepancy_types_cnt2['Security Group'])

    @staticmethod
    def _removed_ports():
        topology = SgMockProjectSepTest.topology
        return [
            topology.normal_portl2_project1['id'],
            topology.normal_portl2_project2['id'],
            topology.normal_portl3_project1['id'],
            topology.normal_portl3_project2['id'],
            topology.normal_port_no_securityl2_project1['id'],
            topology.normal_port_no_securityl2_project2['id'],
            topology.normal_port_no_securityl3_project1['id'],
            topology.normal_port_no_securityl3_project2['id'],
            topology.hw_port_l2_project1['id'],
            topology.hw_port_l2_project2['id'],
            topology.hw_port_l3_project1['id'],
            topology.hw_port_l3_project2['id']
        ]

    def _mock_get_vports_missing_vport(self, parent=None, vspk_filter=None):
        # Note that since we use mocking, self is the NeutronClient
        removed_ports = SgMockProjectSepTest._removed_ports()
        external_id_func = (SgMockProjectSepTest.topology.vsd.vspk_helper
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
        audit_report, observed_in_sync = self.sut.audit_sg()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_in_sync['vports'] -= 8
        expected_in_sync['vports (PG_FOR_LESS)'] -= 4
        self.assert_counter_equal(expected_in_sync, observed_in_sync)
        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        expected_in_sync['vports'] -= 4
        expected_in_sync['vports (PG_FOR_LESS)'] -= 2
        self.assert_counter_equal(expected_in_sync, observed_in_sync1)
        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        expected_in_sync['vports'] -= 4
        expected_in_sync['vports (PG_FOR_LESS)'] -= 2
        self.assert_counter_equal(expected_in_sync, observed_in_sync2)

        removed_ports = SgMockProjectSepTest._removed_ports()

        self.assert_audit_report_length(len(removed_ports), audit_report)
        self.assert_audit_report_length(len(removed_ports) / 2, audit_report1)
        self.assert_audit_report_length(len(removed_ports) / 2, audit_report2)

        for discrepancy in audit_report:
            self.assert_equal('ORPHAN_NEUTRON_ENTITY',
                              discrepancy['discrepancy_type'])
            self.assert_equal('Security Group port',
                              discrepancy['entity_type'])
            self.assertIn(discrepancy['neutron_entity'], removed_ports)
            self.assertIsNone(discrepancy['vsd_entity'])

        for discrepancy in audit_report1:
            self.assert_equal('ORPHAN_NEUTRON_ENTITY',
                              discrepancy['discrepancy_type'])
            self.assert_equal('Security Group port',
                              discrepancy['entity_type'])
            self.assertIn(discrepancy['neutron_entity'], removed_ports)
            self.assertIsNone(discrepancy['vsd_entity'])

        for discrepancy in audit_report2:
            self.assert_equal('ORPHAN_NEUTRON_ENTITY',
                              discrepancy['discrepancy_type'])
            self.assert_equal('Security Group port',
                              discrepancy['entity_type'])
            self.assertIn(discrepancy['neutron_entity'], removed_ports)
            self.assertIsNone(discrepancy['vsd_entity'])

        self.assert_all_different([discrepancy['neutron_entity']
                                   for discrepancy in audit_report])

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
        audit_report, observed_in_sync = self.sut.audit_sg()
        audit_report1, observed_in_sync2 = self.sut_project_1.audit_sg()
        audit_report2, observed_in_sync1 = self.sut_project_2.audit_sg()

        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] = 0
        expected_in_sync['egress_acl_entry_templates (PG_FOR_LESS)'] = 0
        expected_in_sync['egress_acl_entry_templates'] = 0
        expected_in_sync['ingress_acl_entry_templates'] = 0
        expected_in_sync['egress_acl_entry_templates (hardware)'] = 0
        self.assert_counter_equal(expected_in_sync, observed_in_sync)

        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] = 0
        expected_in_sync['egress_acl_entry_templates (PG_FOR_LESS)'] = 0
        expected_in_sync['egress_acl_entry_templates'] = 0
        expected_in_sync['ingress_acl_entry_templates'] = 0
        expected_in_sync['egress_acl_entry_templates (hardware)'] = 0

        self.assert_counter_equal(expected_in_sync, observed_in_sync1)
        self.assert_counter_equal(expected_in_sync, observed_in_sync2)

        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_discrepancies = (
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] +
            expected_in_sync['egress_acl_entry_templates (PG_FOR_LESS)'] +
            expected_in_sync['egress_acl_entry_templates'] +
            expected_in_sync['ingress_acl_entry_templates'] +
            expected_in_sync['egress_acl_entry_templates (hardware)'])
        self.assert_audit_report_length(expected_discrepancies, audit_report)

        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        expected_discrepancies = (
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] +
            expected_in_sync['egress_acl_entry_templates (PG_FOR_LESS)'] +
            expected_in_sync['egress_acl_entry_templates'] +
            expected_in_sync['ingress_acl_entry_templates'] +
            expected_in_sync['egress_acl_entry_templates (hardware)'])
        self.assert_audit_report_length(expected_discrepancies, audit_report1)
        self.assert_audit_report_length(expected_discrepancies, audit_report2)

        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_mismatches = (
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] +
            expected_in_sync['egress_acl_entry_templates (PG_FOR_LESS)'])
        expected_orphans = (
            expected_in_sync['egress_acl_entry_templates'] +
            expected_in_sync['ingress_acl_entry_templates'] +
            expected_in_sync['egress_acl_entry_templates (hardware)'])

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
        self.assert_equal(expected_mismatches, mismatch,
                          'Exactly {} entity mismatches expected, found {}')
        self.assert_equal(expected_orphans, orphan,
                          'Exactly {} neutron orphans expected, found {}')

        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        expected_mismatches = (
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] +
            expected_in_sync['egress_acl_entry_templates (PG_FOR_LESS)'])
        expected_orphans = (
            expected_in_sync['egress_acl_entry_templates'] +
            expected_in_sync['ingress_acl_entry_templates'] +
            expected_in_sync['egress_acl_entry_templates (hardware)'])

        mismatch = 0
        orphan = 0
        for discrepancy in audit_report1:
            if discrepancy['discrepancy_type'] == 'ENTITY_MISMATCH':
                mismatch += 1
            elif discrepancy['discrepancy_type'] == 'ORPHAN_NEUTRON_ENTITY':
                orphan += 1
            else:
                self.fail("Discrepancy type {} unexpected.".format(
                    discrepancy['discrepancy_type']))
        self.assert_equal(expected_mismatches, mismatch,
                          'Exactly {} entity mismatches expected, found {}')

        self.assert_equal(expected_orphans, orphan,
                          'Exactly {} neutron orphans expected, found {}')
        mismatch = 0
        orphan = 0
        for discrepancy in audit_report2:
            if discrepancy['discrepancy_type'] == 'ENTITY_MISMATCH':
                mismatch += 1
            elif discrepancy['discrepancy_type'] == 'ORPHAN_NEUTRON_ENTITY':
                orphan += 1
            else:
                self.fail("Discrepancy type {} unexpected.".format(
                    discrepancy['discrepancy_type']))
        self.assert_equal(expected_mismatches, mismatch,
                          'Exactly {} entity mismatches expected, found {}')

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
        audit_report, observed_in_sync = self.sut.audit_sg()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

        # Expected: pg for less + port with no port security
        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_in_sync.pop('egress_acl_entry_templates')
        expected_in_sync.pop('ingress_acl_entry_templates')
        expected_in_sync.pop('policygroups')
        expected_in_sync.pop('vports')
        self.assert_counter_equal(expected_in_sync, observed_in_sync)

        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        expected_in_sync.pop('egress_acl_entry_templates')
        expected_in_sync.pop('ingress_acl_entry_templates')
        expected_in_sync.pop('policygroups')
        expected_in_sync.pop('vports')
        self.assert_counter_equal(expected_in_sync, observed_in_sync1)
        self.assert_counter_equal(expected_in_sync, observed_in_sync2)

        expected_discrepancies = (
            self.get_default_expected_in_sync_counter()['policygroups'])
        self.assert_audit_report_length(expected_discrepancies, audit_report)

        expected_discrepancies = (
            self.get_per_project_expected_in_sync_counter()['policygroups'])
        self.assert_audit_report_length(expected_discrepancies, audit_report1)
        self.assert_audit_report_length(expected_discrepancies, audit_report2)

        for discrepancy in audit_report:
            self.assert_equal('ENTITY_MISMATCH',
                              discrepancy['discrepancy_type'])
        for discrepancy in audit_report1:
            self.assert_equal('ENTITY_MISMATCH',
                              discrepancy['discrepancy_type'])
        for discrepancy in audit_report2:
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
        audit_report, observed_in_sync = self.sut.audit_sg()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_in_sync['egress_acl_entry_templates'] = 0
        expected_in_sync['ingress_acl_entry_templates'] = 0
        self.assert_counter_equal(expected_in_sync, observed_in_sync)

        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        expected_in_sync['egress_acl_entry_templates'] = 0
        expected_in_sync['ingress_acl_entry_templates'] = 0
        self.assert_counter_equal(expected_in_sync, observed_in_sync1)
        self.assert_counter_equal(expected_in_sync, observed_in_sync2)

        expected_in_sync = self.get_default_expected_in_sync_counter()
        expected_discrepancies = (
            expected_in_sync['ingress_acl_entry_templates'] +
            expected_in_sync['egress_acl_entry_templates'])
        self.assert_audit_report_length(expected_discrepancies, audit_report)

        expected_in_sync = self.get_per_project_expected_in_sync_counter()
        expected_discrepancies = (
            expected_in_sync['ingress_acl_entry_templates'] +
            expected_in_sync['egress_acl_entry_templates'])
        self.assert_audit_report_length(expected_discrepancies, audit_report1)
        self.assert_audit_report_length(expected_discrepancies, audit_report2)

        for discrepancy in audit_report:
            self.assert_equal('ENTITY_MISMATCH',
                              discrepancy['discrepancy_type'])
        for discrepancy in audit_report1:
            self.assert_equal('ENTITY_MISMATCH',
                              discrepancy['discrepancy_type'])
        for discrepancy in audit_report2:
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
            audit_report, observed_in_sync = self.sut.audit_sg()
            audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
            audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

            # discrepancy validation
            # there are 2 orphans per domain, an IPv4 and IPv6 ingress rule
            expected_discrepancies = self.topology.counter['domains'] * 2 \
                if self.topology.pg_for_less_active else 0
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            expected_discrepancies /= 2
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report1)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report2)

            for entry in audit_report:
                self.assertEqual('ORPHAN_VSD_ENTITY',
                                 entry['discrepancy_type'])
            for entry in audit_report1:
                self.assertEqual('ORPHAN_VSD_ENTITY',
                                 entry['discrepancy_type'])
            for entry in audit_report2:
                self.assertEqual('ORPHAN_VSD_ENTITY',
                                 entry['discrepancy_type'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            self.assert_counter_equal(expected_in_sync, observed_in_sync)
            expected_in_sync = self.get_per_project_expected_in_sync_counter()
            self.assert_counter_equal(expected_in_sync, observed_in_sync1)
            self.assert_counter_equal(expected_in_sync, observed_in_sync2)

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
            audit_report, observed_in_sync = self.sut.audit_sg()
            audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
            audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

            # discrepancy validation
            # there are 2 mismatches per domain, an IPv4 and IPv6 ingress rule
            expected_discrepancies = self.topology.counter['domains'] * 2 \
                if self.topology.pg_for_less_active else 0
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            expected_discrepancies /= 2
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report1)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report2)
            for entry in audit_report + audit_report1 + audit_report2:
                self.assertEqual('ENTITY_MISMATCH',
                                 entry['discrepancy_type'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync)
            expected_in_sync = self.get_per_project_expected_in_sync_counter()

            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync1)
            self.assert_counter_equal(expected_in_sync, observed_in_sync2)

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
            audit_report, observed_in_sync = self.sut.audit_sg()
            audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
            audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

            # discrepancy validation
            # there are 4 mismatches per domain, invalid rule for IPv4 and IPv6
            # and detection of missing entry for IPv4 and IPv6
            expected_discrepancies = self.topology.counter['domains'] * 4 \
                if self.topology.pg_for_less_active else 0
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            expected_discrepancies /= 2
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report1)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report2)

            for entry in audit_report + audit_report1 + audit_report2:
                self.assertEqual('ENTITY_MISMATCH',
                                 entry['discrepancy_type'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

            expected_in_sync = self.get_per_project_expected_in_sync_counter()
            expected_in_sync['ingress_acl_entry_templates (PG_FOR_LESS)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync1)
            self.assert_counter_equal(expected_in_sync, observed_in_sync2)

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
            audit_report, observed_in_sync = self.sut.audit_sg()
            audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
            audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

            # discrepancy validation
            # There is one orphans per domain since each domain has one
            # block-all acl for hardware vports
            expected_discrepancies = (self.topology.counter['domains']
                                      if self.topology.hardware_port else 0)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            expected_discrepancies /= 2
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report1)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report2)

            for entry in audit_report + audit_report1 + audit_report2:
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
            audit_report, observed_in_sync = self.sut.audit_sg()
            audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
            audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()
            INFO.pprint(audit_report)

            # discrepancy validation
            # Normally we have one entry per domain, since we doubled the
            # entries there is now one excess entry per domain
            expected_discrepancies = (self.topology.counter['domains']
                                      if self.topology.hardware_port else 0)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            expected_discrepancies /= 2
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report1)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report2)

            for entry in audit_report + audit_report1 + audit_report2:
                self.assertEqual('ORPHAN_VSD_ENTITY',
                                 entry['discrepancy_type'])
                self.assertEqual('Hardware block-all ACL '
                                 'has more than one rule',
                                 entry['discrepancy_details'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            self.assert_counter_equal(expected_in_sync, observed_in_sync)
            expected_in_sync = self.get_per_project_expected_in_sync_counter()
            self.assert_counter_equal(expected_in_sync, observed_in_sync1)
            self.assert_counter_equal(expected_in_sync, observed_in_sync2)

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
            audit_report, observed_in_sync = self.sut.audit_sg()
            audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
            audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

            # discrepancy validation
            # There is one mismatch per domain since each domain has one
            # block-all acl with one rule for hardware vports
            expected_discrepancies = (self.topology.counter['domains']
                                      if self.topology.hardware_port else 0)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report)
            expected_discrepancies /= 2
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report1)
            self.assert_audit_report_length(expected_discrepancies,
                                            audit_report2)

            for entry in audit_report + audit_report1 + audit_report2:
                self.assertEqual('ENTITY_MISMATCH',
                                 entry['discrepancy_type'])
                self.assertEqual('Invalid rule for hardware block-all acl',
                                 entry['discrepancy_details'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['egress_acl_entry_templates (hardware)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync)

            expected_in_sync = self.get_per_project_expected_in_sync_counter()
            expected_in_sync['egress_acl_entry_templates (hardware)'] = 0
            self.assert_counter_equal(expected_in_sync, observed_in_sync1)
            self.assert_counter_equal(expected_in_sync, observed_in_sync2)

    @header()
    def test_port_security_mismatch(self):
        if self.topology.is_dhcp_agent_enabled():
            self.skipTest("Running this test with DHCP agent enabled is not "
                          "supported")
        original_getter = NeutronClient.get_ports

        def mock_get_ports_missing_port_security(*args, **kwargs):
            ports = original_getter(*args, **kwargs)
            port = next(
                (port for port in ports
                 if (port.get('id') ==
                     self.topology.normal_portl3_project1['id'] or
                     port.get('id') == self.topology.normal_portl3_project2[
                         'id'])),
                None)
            if port:
                self.assertIs(True, port.get('port_security_enabled'))
                port['port_security_enabled'] = False
                port['security_groups'] = []
            return ports

        with mock.patch.object(
                NeutronClient, 'get_ports',
                new=mock_get_ports_missing_port_security):
            # audit
            audit_report, observed_in_sync = self.sut.audit_sg()
            audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
            audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

            # discrepancy validation
            # The neutron port is not linked anymore with the vPort,
            # so we have one neutron orphan and one VSD orphan per tenant
            self.assert_audit_report_length(4, audit_report)
            self.assert_equal(
                expected={'ORPHAN_VSD_ENTITY', 'ORPHAN_NEUTRON_ENTITY'},
                observed={discrepancy['discrepancy_type']
                          for discrepancy in audit_report})
            neutron_discrepancies = [
                discrepancy['neutron_entity'] for discrepancy in audit_report
                if discrepancy['discrepancy_type'] == 'ORPHAN_NEUTRON_ENTITY']
            self.assertIn(self.topology.normal_portl3_project1['id'],
                          neutron_discrepancies)
            self.assertIn(self.topology.normal_portl3_project2['id'],
                          neutron_discrepancies)

            # No VSD orphan detected in project isolation mode
            self.assert_audit_report_length(1, audit_report1)
            self.assert_audit_report_length(1, audit_report2)
            for entry in audit_report1 + audit_report2:
                self.assertEqual('ORPHAN_NEUTRON_ENTITY',
                                 entry['discrepancy_type'])
            self.assertEqual(self.topology.normal_portl3_project1['id'],
                             audit_report1[0]['neutron_entity'])
            self.assertEqual(self.topology.normal_portl3_project2['id'],
                             audit_report2[0]['neutron_entity'])

            # in sync validation
            expected_in_sync = self.get_default_expected_in_sync_counter()
            expected_in_sync['vports'] -= 2
            self.assert_counter_equal(expected_in_sync, observed_in_sync)
            expected_in_sync = self.get_per_project_expected_in_sync_counter()
            expected_in_sync['vports'] -= 1
            self.assert_counter_equal(expected_in_sync, observed_in_sync1)
            self.assert_counter_equal(expected_in_sync, observed_in_sync2)

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
        audit_report, observed_in_sync = self.sut.audit_sg()
        audit_report1, observed_in_sync1 = self.sut_project_1.audit_sg()
        audit_report2, observed_in_sync2 = self.sut_project_2.audit_sg()

        # Nothing is in sync, we cut of early in case of missing domain
        self.assert_counter_equal(Counter(), observed_in_sync)
        self.assert_counter_equal(Counter(), observed_in_sync1)
        self.assert_counter_equal(Counter(), observed_in_sync2)

        # A discrepancy for each domain
        expected_discrepancies = self.topology.counter['domains']
        self.assertEqual(expected_discrepancies, len(audit_report))
        self.assertEqual(expected_discrepancies / 2, len(audit_report1))
        self.assertEqual(expected_discrepancies / 2, len(audit_report2))

        for discrepancy in audit_report + audit_report1 + audit_report2:
            self.assert_equal('ORPHAN_NEUTRON_ENTITY',
                              discrepancy['discrepancy_type'])
            self.assertIsNone(discrepancy['vsd_entity'])
            self.assertIn(discrepancy['neutron_entity'],
                          [self.topology.router_project1['id'],
                           self.topology.router_project2['id'],
                           self.topology.subnetl2_project1['id'],
                           self.topology.subnetl2_project2['id']])
            if (discrepancy['neutron_entity'] ==
                    self.topology.router_project1['id'] or
                    discrepancy['neutron_entity'] ==
                    self.topology.router_project2['id']):
                self.assert_equal(discrepancy['discrepancy_details'],
                                  'router has no l3-domain')
            else:
                self.assert_equal(discrepancy['discrepancy_details'],
                                  'l2-subnet has no l2-domain')
