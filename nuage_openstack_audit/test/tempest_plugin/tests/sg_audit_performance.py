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
import time
from uuid import uuid4 as uuid

import testtools

# system under test
from nuage_openstack_audit.main import Main as SystemUnderTest

# test code
from nuage_openstack_audit.test.tempest_plugin.services.neutron_test_helper \
    import NeutronTestHelper
from nuage_openstack_audit.test.tempest_plugin.services.neutron_test_helper \
    import OS_CREDENTIALS
from nuage_openstack_audit.test.tempest_plugin.services.vsd_test_helper \
    import CMS_ID
from nuage_openstack_audit.test.tempest_plugin.services.vsd_test_helper \
    import VSD_CREDENTIALS
from nuage_openstack_audit.test.tempest_plugin.tests.base_test import TestBase
from nuage_openstack_audit.test.tempest_plugin.tests.utils.main_args \
    import MainArgs
from nuage_openstack_audit.utils.logger import Reporter

INFO = Reporter('INFO')


def timeit(method):
    def timed(*args, **kwargs):
        start = time.time()
        result = method(*args, **kwargs)
        end = time.time()
        print('{}.{} took {}s'.format(
            args[0].__class__.__name__, method.__name__, int(end - start)))
        return result

    return timed


@testtools.skip("Skipping performance tests")
class ScaleRouterPerfTest(TestBase):
    """Increasing number of security groups"""

    def __init__(self, *args, **kwargs):
        super(ScaleRouterPerfTest, self).__init__(*args, **kwargs)
        self.expected_in_sync = Counter()

    @classmethod
    def setUpClass(cls):
        cls.system_under_test = SystemUnderTest(
            args=MainArgs('security_group'),
            os_credentials=OS_CREDENTIALS,
            vsd_credentials=VSD_CREDENTIALS,
            cms_id=CMS_ID)

        # Neutron
        cls.topology = NeutronTestHelper()
        cls.topology.authenticate()

    def setUp(self):
        super(ScaleRouterPerfTest, self).setUp()

        for _ in range(1100):
            router = self.topology.create_router(name=uuid())
            network = self.topology.create_network(name=uuid())
            subnet = self.topology.create_subnet_l3(
                network_id=network['id'],
                ip_version=4,
                cidr='10.0.0.0/24')
            self.topology.create_router_interface(router_id=router['id'],
                                                  subnet_id=subnet['id'])

            for i in range(3):
                sg = self.topology.create_security_group_used(name=uuid())
                self.topology.create_security_group_rule_stateful(
                    protocol='tcp', security_group_id=sg['id'],
                    ethertype='IPv4', direction='egress',
                    remote_ip_prefix='{}.0.0.0/16'.format(i))
                self.topology.create_security_group_rule_stateful(
                    protocol='tcp', security_group_id=sg['id'],
                    ethertype='IPv4', direction='ingress',
                    remote_ip_prefix='{}.0.0.0/16'.format(i))

                self.topology.create_port(network, security_groups=[sg['id']])

    @classmethod
    def tearDownClass(cls):
        cls.topology.teardown()

    def run_audit(self):
        expected_in_sync = Counter({
            'egress_acl_entry_templates':
                self.topology.counter['sg_rules_ingress'],
            'ingress_acl_entry_templates':
                self.topology.counter['sg_rules_egress'],
            'policygroups':
                self.topology.counter['sgs'],
            'vports': self.topology.counter['ports_sg']
        })

        audit_report, observed_in_sync = self.system_under_test.audit_sg()
        self.check_equal(expected_in_sync, Counter(observed_in_sync),
                         'Wrong amount of entities in sync: '
                         'Expected {}, observed {}'
                         .format(expected_in_sync, observed_in_sync))
        self.check_equal(0, len(audit_report), 'Wrong audit report length, '
                                               'expected {}, got {}')
        INFO.report("Audit report: {}\n Observer in sync: {}"
                    .format(audit_report, observed_in_sync))

    @timeit
    def test_sample_8(self):
        self.run_audit()

    @timeit
    def test_sample_7(self):
        self.run_audit()

    @timeit
    def test_sample_6(self):
        self.run_audit()

    @timeit
    def test_sample_5(self):
        self.run_audit()

    @timeit
    def test_sample_4(self):
        self.run_audit()

    @timeit
    def test_sample_3(self):
        self.run_audit()

    @timeit
    def test_sample_2(self):
        self.run_audit()

    @timeit
    def test_sample_1(self):
        self.run_audit()


@testtools.skip("Skipping performance tests")
class ScaleSGPerfTest(TestBase):
    """Increasing number of security groups"""

    def __init__(self, *args, **kwargs):
        super(ScaleSGPerfTest, self).__init__(*args, **kwargs)
        self.expected_in_sync = Counter()

    @classmethod
    def setUpClass(cls):
        cls.system_under_test = SystemUnderTest(
            args=MainArgs('security_group'),
            os_credentials=OS_CREDENTIALS,
            vsd_credentials=VSD_CREDENTIALS,
            cms_id=CMS_ID)

        # Neutron
        cls.topology = NeutronTestHelper()
        cls.topology.authenticate(SystemUnderTest.get_os_credentials())

        cls.network = cls.topology.create_network(name=uuid())
        cls.topology.create_subnet_l2(
            network_id=cls.network['id'],
            ip_version=4,
            cidr='10.0.0.0/16')

    def setUp(self):
        super(ScaleSGPerfTest, self).setUp()
        for i in range(10):
            sg = self.topology.create_security_group_used(name=uuid())
            self.topology.create_security_group_rule_stateful(
                protocol='tcp', security_group_id=sg['id'],
                ethertype='IPv4', direction='egress',
                remote_ip_prefix='{}.0.0.0/16'.format(i))
            self.topology.create_security_group_rule_stateful(
                protocol='tcp', security_group_id=sg['id'],
                ethertype='IPv4', direction='ingress',
                remote_ip_prefix='{}.0.0.0/16'.format(i))

            self.topology.create_port(self.network, security_groups=[sg['id']])

    @classmethod
    def tearDownClass(cls):
        cls.topology.teardown()

    def run_audit(self):
        expected_in_sync = Counter({
            'egress_acl_entry_templates':
                self.topology.counter['sg_rules_ingress'],
            'ingress_acl_entry_templates':
                self.topology.counter['sg_rules_egress'],
            'policygroups':
                self.topology.counter['sgs'],
            'vports': self.topology.counter['ports_sg']
        })

        audit_report, observed_in_sync = self.system_under_test.audit_sg()
        self.check_equal(expected_in_sync, Counter(observed_in_sync),
                         'Wrong amount of entities in sync: '
                         'Expected {}, observed {}'
                         .format(expected_in_sync, observed_in_sync))
        self.check_equal(0, len(audit_report), 'Wrong audit report length, '
                                               'expected {}, got {}')
        INFO.report("Audit report: {}\n Observer in sync: {}"
                    .format(audit_report, observed_in_sync))

    @timeit
    def test_sample_8(self):
        self.run_audit()

    @timeit
    def test_sample_7(self):
        self.run_audit()

    @timeit
    def test_sample_6(self):
        self.run_audit()

    @timeit
    def test_sample_5(self):
        self.run_audit()

    @timeit
    def test_sample_4(self):
        self.run_audit()

    @timeit
    def test_sample_3(self):
        self.run_audit()

    @timeit
    def test_sample_2(self):
        self.run_audit()

    @timeit
    def test_sample_1(self):
        self.run_audit()