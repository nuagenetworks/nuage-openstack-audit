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

import mock
import pprint

import testtools
from nuage_openstack_audit.test.utils.decorators import header

# system under test
from nuage_openstack_audit.main import Main  # system under test
from nuage_openstack_audit.osclient.osclient import Neutron  # for mocking
from nuage_openstack_audit.vsdclient.vsdclient import VsdClient  # for mocking

# test code
from nuage_openstack_audit.osclient.osclient import OSCredentials  # reused
from nuage_openstack_audit.osclient.osclient import Keystone  # reused
from nuage_openstack_audit.test.utils.neutron_test_helper \
    import NeutronTestHelper
from nuage_openstack_audit.utils.utils import Utils
from nuage_openstack_audit.vsdclient.common.vspk_helper import VspkHelper
from nuage_openstack_audit.test.utils.vsd_test_helper import VSDTestHelper

from nuage_openstack_audit.test.utils.main_args import MainArgs

# run me using:
# python -m testtools.run nuage_openstack_audit/test/sg_audit_test.py

# *****************************************************************************
#  CAUTION : THIS IS NOT A REAL UNIT TEST ; IT REQUIRES A FULL OS-VSD SETUP,
#            SETUP WITH AUDIT ENV VARIABLES CORRECTLY SET.
# *****************************************************************************


def get_vsd_client():
    user, password = Utils.get_env_var(
        'OS_VSD_SERVER_AUTH', 'csproot:csproot').split(':')
    return VSDTestHelper(
        vsd_server=Utils.get_env_var('OS_VSD_SERVER'),
        user=user,
        password=password,
        base_uri=Utils.get_env_var('OS_VSD_BASE_URI', '/nuage/api/v5_0'),
        cms_id=Utils.get_env_var('OS_CMS_ID'),
        enterprise=Utils.get_env_var('OS_DEFAULT_NETPARTITION'))


class SGRulesAuditTest(testtools.TestCase):

    main = None

    neutron = None
    router = None
    networkl3 = None
    subnetl3 = None
    networkl2 = None
    subnetl2 = None
    nr_domains = 0

    sg = None
    sg_rule = None
    sg_hw_port = None
    sg_rule_hw = None
    nr_sgs = 0
    nr_sg_rules = 0
    nr_sg_rules_icmp = 0

    normal_portl3 = None
    normal_port2l3 = None
    normal_port_no_securityl3 = None
    hw_port_l3 = None
    normal_portl2 = None
    normal_port2l2 = None
    normal_port_no_securityl2 = None
    hw_port_l2 = None
    nr_ports_sg = 0
    nr_ports_no_security = 0
    pg_for_less_active = False
    hardware_port = False

    vsd = None
    domain = None
    policy_group = None

    @classmethod
    def setUpClass(cls):
        super(SGRulesAuditTest, cls).setUpClass()

        # vsd entities
        # TODO Check discrepancies with correctness of ID
        cls.vsd = get_vsd_client()
        # cls.l3domain = cls.vsd.get_l3domain(by_neutron_id=cls.router['id'])
        # cls.l3policy_group = cls.vsd.get_policy_group(
        #     domain=cls.domain, by_neutron_id=cls.sg['id'])

        cls.gateway = cls.vsd.create_gateway(name='vsg', system_id='my-sys_id',
                                             personality='VSG')
        cls.gw_port1 = cls.vsd.create_gateway_port(cls.gateway,
                                                   name='gw-port-1',
                                                   user_mnemonic='gw-port-1',
                                                   vlan_range='0-4095',
                                                   physical_name='gw-port-1',
                                                   port_type='ACCESS')
        cls.gw_port2 = cls.vsd.create_gateway_port(cls.gateway,
                                                   name='gw-port-2',
                                                   user_mnemonic='gw-port-2',
                                                   vlan_range='0-4095',
                                                   physical_name='gw-port-2',
                                                   port_type='ACCESS')

        # neutron entities
        cls.neutron = NeutronTestHelper(Keystone(OSCredentials()))
        cls.router = cls.neutron.create_router(name='test-router')
        cls.nr_domains += 1

        cls.networkl3 = cls.neutron.create_network(name='test-networkl3')
        cls.networkl2 = cls.neutron.create_network(name='test-networkl2')
        cls.subnetl3 = cls.neutron.create_subnet(
            network_id=cls.networkl3['id'],
            ip_version=4,
            cidr='10.0.0.0/24')
        cls.subnetl2 = cls.neutron.create_subnet(
            network_id=cls.networkl2['id'],
            ip_version=4,
            cidr='10.0.0.0/24')
        cls.nr_domains += 1

        cls.neutron.create_router_interface(router_id=cls.router['id'],
                                            subnet_id=cls.subnetl3['id'])
        cls.sg = cls.neutron.create_security_group(name="test-sg")
        cls.nr_sgs += 1
        cls.nr_sg_rules += 2  # default rules
        cls.sg_rule = cls.neutron.create_security_group_rule(
            protocol='icmp', security_group_id=cls.sg['id'])
        cls.nr_sg_rules_icmp += 1

        cls.sg_hw_port = cls.neutron.create_security_group(name="test-sg-hw")
        cls.nr_sgs += 1
        cls.nr_sg_rules += 2  # default rules
        cls.sg_rule_hw = cls.neutron.create_security_group_rule(
            protocol='icmp', security_group_id=cls.sg_hw_port['id'])
        cls.nr_sg_rules += 1  # HW ICMP is stateless

        # Ports
        # l3
        cls.normal_portl3 = cls.neutron.create_port(
            cls.networkl3, security_groups=[cls.sg['id']],
            name='normal_port1')
        cls.normal_port2l3 = cls.neutron.create_port(
            cls.networkl3, security_groups=[cls.sg['id']],
            name='normal_port2')
        cls.normal_port_no_securityl3 = cls.neutron.create_port(
            cls.networkl3, port_security_enabled=False,
            name='normal_port_no_security')
        hw_port_args = {
            'name': 'hw-port',
            'security_groups': [cls.sg_hw_port['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": cls.gw_port1.name,
                     "switch_info": cls.gateway.system_id}]
            }}
        cls.hw_port_l3 = cls.neutron.create_port(cls.networkl3, **hw_port_args)
        cls.nr_ports_sg += 3
        cls.nr_ports_no_security += 1

        # Normal ports l2
        cls.normal_portl2 = cls.neutron.create_port(
            cls.networkl2, security_groups=[cls.sg['id']],
            name='normal_port1')
        cls.normal_port2l2 = cls.neutron.create_port(
            cls.networkl2, security_groups=[cls.sg['id']],
            name='normal_port2')
        cls.normal_port_no_securityl2 = cls.neutron.create_port(
            cls.networkl2, port_security_enabled=False,
            name='normal_port_no_security')
        hw_port_args = {
            'name': 'hw-port',
            'security_groups': [cls.sg_hw_port['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                "local_link_information": [
                    {"port_id": cls.gw_port2.name,
                     "switch_info": cls.gateway.system_id}]
            }}
        cls.hw_port_l2 = cls.neutron.create_port(cls.networkl2, **hw_port_args)
        cls.nr_ports_sg += 3
        cls.nr_ports_no_security += 1

        cls.pg_for_less_active = True
        cls.hardware_port = True

        print('\n=== Launching system under test')
        cls.main = Main(MainArgs('security_group'))

    @classmethod
    def tearDownClass(cls):
        super(SGRulesAuditTest, cls).tearDownClass()
        cls.neutron.delete_port(cls.normal_portl3['id'])
        cls.neutron.delete_port(cls.normal_port2l3['id'])
        cls.neutron.delete_port(cls.normal_port_no_securityl3['id'])
        cls.neutron.delete_port(cls.normal_portl2['id'])
        cls.neutron.delete_port(cls.normal_port2l2['id'])
        cls.neutron.delete_port(cls.normal_port_no_securityl2['id'])
        cls.neutron.delete_port(cls.hw_port_l3['id'])
        cls.neutron.delete_port(cls.hw_port_l2['id'])

        cls.neutron.delete_security_group_rule(cls.sg_rule['id'])
        cls.neutron.delete_security_group_rule(cls.sg_rule_hw['id'])
        cls.neutron.delete_security_group(cls.sg['id'])
        cls.neutron.delete_security_group(cls.sg_hw_port['id'])
        cls.neutron.delete_router_interface(router_id=cls.router['id'],
                                            subnet_id=cls.subnetl3['id'])
        cls.neutron.delete_subnet(cls.subnetl3['id'])
        cls.neutron.delete_network(cls.networkl3['id'])
        cls.neutron.delete_router(cls.router)
        cls.neutron.delete_subnet(cls.subnetl2['id'])
        cls.neutron.delete_network(cls.networkl2['id'])

        cls.gw_port1.delete()
        cls.gw_port2.delete()
        cls.gateway.delete()

    @header()
    def test_no_discrepancies(self):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        expected_in_sync = (self.nr_ports_sg +
                            self.nr_domains * (self.nr_sgs +
                                               self.nr_sg_rules +
                                               self.nr_sg_rules_icmp * 2) +
                            self.pg_for_less_active * 4 * self.nr_domains +
                            self.hardware_port * self.nr_domains +
                            self.nr_ports_no_security)
        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))
        # expecting zero discrepancies
        self.assertEqual(0, len(audit_report))

    @mock.patch.object(VsdClient, 'get_policy_groups',
                       return_value=[])
    @header()
    def test_policygroup_orphan(self, *_):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        # Expected in sync: Hardware acl is audited separately
        expected_in_sync = self.hardware_port * self.nr_domains
        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))

        # no port security will still be checked
        expected_discrepancies = (self.nr_sgs * self.nr_domains +
                                  self.nr_ports_no_security +
                                  self.pg_for_less_active * self.nr_domains)
        self.assertEqual(expected_discrepancies, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual('ORPHAN_NEUTRON_ENTITY',
                             discrepancy['discrepancy_type'])

    def _mock_missing_port_sg(self, filters=None, fields=None):
        # Leave out self.normal_port but otherwise execute as normal
        kwargs = {}
        if filters:
            kwargs = filters
        # Ignore fields passed as we do need the name field for testing
        ports = self.client.list_ports(**kwargs)['ports']
        for port in ports:
            port['security_groups'] = []
        return ports

    @mock.patch.object(Neutron, 'get_ports',
                       _mock_missing_port_sg)
    @header()
    def test_sg_orphan(self, *_):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        # Expected: pg for less + port with no port security
        expected_in_sync = (self.pg_for_less_active * 4 * self.nr_domains +
                            self.nr_ports_no_security)
        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))

        # Expected discrepancies: 1 missing PG per domain
        expected_discrepancies = self.nr_sgs * self.nr_domains
        self.assertEqual(expected_discrepancies, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual('ORPHAN_VSD_ENTITY',
                             discrepancy['discrepancy_type'])

    def _mock_missing_port(self, filters=None, fields=None):
        # Leave out self.normal_port but otherwise execute as normal
        kwargs = {}
        if filters:
            kwargs = filters
        # Ignore fields passed as we do need the name field for testing
        ports = self.client.list_ports(**kwargs)['ports']
        return [p for p in ports if p['name'] != 'normal_port1']

    @mock.patch.object(Neutron, 'get_ports',
                       _mock_missing_port)
    @header()
    def test_port_orphan(self, *_):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        # Expected in sync: -2 because of the normal_port1 being excluded
        expected_in_sync = (self.nr_ports_sg +
                            self.nr_domains * (self.nr_sgs +
                                               self.nr_sg_rules +
                                               self.nr_sg_rules_icmp * 2) +
                            self.pg_for_less_active * 4 * self.nr_domains +
                            self.hardware_port * self.nr_domains +
                            self.nr_ports_no_security) - 2
        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))

        # Expected discrepancies: 2 ports missing
        expected_discrepancies = 2
        self.assertEqual(expected_discrepancies, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual('ORPHAN_VSD_ENTITY',
                             discrepancy['discrepancy_type'])

    def _mock_missing_vport(self, parent=None, vspk_filter=None):
        vports = VspkHelper.get_all(
            parent=self.vspk_helper.get_default_enterprise()
            if parent is None else parent,
            filter=vspk_filter,
            fetcher_str="vports")
        # do not work with generator here because of limited scope of testing
        return list(vports)[:-1]

    @mock.patch.object(VsdClient, 'get_vports',
                       new=_mock_missing_vport)
    @header()
    def test_vport_orphan(self, *_):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        expected_in_sync = (self.nr_ports_sg +
                            self.nr_domains * (self.nr_sgs +
                                               self.nr_sg_rules +
                                               self.nr_sg_rules_icmp * 2) +
                            self.pg_for_less_active * 4 * self.nr_domains +
                            self.hardware_port * self.nr_domains +
                            self.nr_ports_no_security -
                            # 1 less per SG
                            self.nr_sgs * self.nr_domains -
                            # Additionally 1 less for PG_FOR_LESS
                            self.pg_for_less_active * self.nr_domains)

        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))
        # Expected discrepancies: 1 missing PG
        expected_discrepancies = (self.nr_sgs * self.nr_domains +
                                  self.pg_for_less_active * self.nr_domains)
        self.assertEqual(expected_discrepancies, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual('ORPHAN_NEUTRON_ENTITY',
                             discrepancy['discrepancy_type'])

    def _mock_missing_sg_rule(self, sg_id):
        sg = self.client.show_security_group(sg_id)['security_group']
        sg['security_group_rules'] = []
        return sg

    @mock.patch.object(Neutron, 'get_security_group',
                       new=_mock_missing_sg_rule)
    @header()
    def test_sg_rule_orphan(self, *_):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        expected_in_sync = (self.nr_ports_sg +
                            self.nr_domains * self.nr_sgs +
                            self.nr_ports_no_security +
                            self.pg_for_less_active * 4 * self.nr_domains +
                            self.hardware_port * self.nr_domains)
        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))

        # Expected discrepancies: 1 missing sg_rule but icmp so 2 vsd orphans
        # Additionally the two default rules for the sg have orphans as well
        expected_discrepancies = (self.nr_domains * (self.nr_sg_rules +
                                                     self.nr_sg_rules_icmp * 2)
                                  )

        self.assertEqual(expected_discrepancies, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual('ORPHAN_VSD_ENTITY',
                             discrepancy['discrepancy_type'])

    @mock.patch.object(VsdClient, 'get_ingress_acl_entries',
                       return_value=[])
    @mock.patch.object(VsdClient, 'get_egress_acl_entries',
                       return_value=[])
    @mock.patch.object(VsdClient, 'get_egress_acl_entries_by_acl',
                       return_value=[])
    @header()
    def test_acl_entry_orphan(self, *_):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        expected_in_sync = (self.nr_ports_sg +
                            self.nr_domains * self.nr_sgs +
                            self.nr_ports_no_security)
        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))

        expected_discrepancies = (
            self.nr_domains * (self.nr_sg_rules +
                               self.nr_sg_rules_icmp * 2) +
            self.pg_for_less_active * 4 * self.nr_domains +
            self.hardware_port * self.nr_domains
        )
        self.assertEqual(expected_discrepancies, len(audit_report))
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
        expected_mismatches = self.pg_for_less_active * 4 * self.nr_domains
        self.assertEqual(expected_mismatches, mismatch,
                         "Exactly {} entity mismatches"
                         "expected, found {}".format(expected_mismatches,
                                                     mismatch))
        expected_orphans = (self.nr_domains * (self.nr_sg_rules +
                                               self.nr_sg_rules_icmp * 2) +
                            self.hardware_port * self.nr_domains)
        self.assertEqual(expected_orphans, orphan,
                         "Exactly {} neutron orphans "
                         "expected, found {}".format(expected_orphans, orphan))

    def mock_changed_sg(self, sg_id):
        sg = self.client.show_security_group(sg_id)['security_group']
        sg['name'] = ''
        return sg

    @mock.patch.object(Neutron, 'get_security_group',
                       new=mock_changed_sg)
    @header()
    def test_sg_discrepancy(self, *_):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        # Expected: pg for less + port with no port security
        expected_in_sync = (self.pg_for_less_active * 4 * self.nr_domains +
                            self.hardware_port * self.nr_domains +
                            self.nr_ports_no_security)
        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))
        expected_discrepancies = self.nr_sgs * self.nr_domains
        self.assertEqual(expected_discrepancies, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual('ENTITY_MISMATCH',
                             discrepancy['discrepancy_type'])

    def mock_changed_sg_rule(self, sg_id):
        sg = self.client.show_security_group(sg_id)['security_group']
        for sg_rule in sg['security_group_rules']:
            sg_rule['port_range_min'] = 1
            sg_rule['port_range_max'] = 1
            if not sg_rule['protocol']:
                sg_rule['protocol'] = 'tcp'
        return sg

    @mock.patch.object(Neutron, 'get_security_group',
                       new=mock_changed_sg_rule)
    @header()
    def test_sg_rule_discrepancy(self, *_):
        audit_report, nr_in_sync = self.main.run()
        pprint.pprint(audit_report)
        # expected not in sync: ICMP rule * 2 * nr domains
        expected_in_sync = (self.nr_ports_sg +
                            self.nr_domains * self.nr_sgs +
                            self.pg_for_less_active * 4 * self.nr_domains +
                            self.hardware_port * self.nr_domains +
                            self.nr_ports_no_security)
        self.assertEqual(expected_in_sync, nr_in_sync,
                         "Entities in sync: actual {}, expected: {}".format(
                             nr_in_sync, expected_in_sync))
        pprint.pprint(audit_report)
        # discrepancies: icmp rule -> tcp rule + one orphan doubled icmp rule
        expected_discrepancies = (self.nr_domains * self.nr_sg_rules +
                                  self.nr_domains * self.nr_sg_rules_icmp * 2)
        self.assertEqual(expected_discrepancies, len(audit_report))
        for discrepancy in audit_report:
            self.assertEqual('ENTITY_MISMATCH',
                             discrepancy['discrepancy_type'])
