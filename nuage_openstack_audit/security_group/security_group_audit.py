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

from collections import Counter
from collections import defaultdict

import six

from nuage_openstack_audit.audit import Audit
from nuage_openstack_audit.security_group.modules.hardware \
    import HardwarePGAudit
from nuage_openstack_audit.security_group.modules.pg_allow_all \
    import PGAllowAllAudit
from nuage_openstack_audit.security_group.security_group_matchers \
    import SecurityGroupPolicyGroupMatcher
from nuage_openstack_audit.security_group.security_group_matchers \
    import SecurityGroupPortsPolicyGroupVportsMatcher
from nuage_openstack_audit.security_group.security_group_matchers \
    import SecurityGroupRuleAclTemplateEntryMatcher
from nuage_openstack_audit.utils import logger
from nuage_openstack_audit.utils.timeit import TimeIt
from nuage_openstack_audit.utils.utils import Utils
from nuage_openstack_audit.vsdclient.common import constants

INFO = logger.Reporter('INFO')
WARN = logger.Reporter('WARN')

ACL_TEMPLATE_SOFTWARE = constants.SOFTWARE
ACL_TEMPLATE_HARDWARE = constants.HARDWARE

AUTO_CREATE_PORT_OWNERS = ['network:router_interface',
                           'network:router_gateway', 'network:floatingip',
                           'nuage:vip', 'compute:ironic', 'network:dhcp:nuage']

PG_ALLOW_ALL = 'PG_ALLOW_ALL'


class SGPortsTuple(object):
    """A custom named tuple initialized with empty list of ports"""
    def __init__(self, security_group=None, ports=None):
        self.security_group = security_group
        self.ports = ports if ports else []

    def __getitem__(self, index):
        if index == 0:
            return self.security_group
        elif index == 1:
            return self.ports
        else:
            raise IndexError


class SecurityGroupAudit(Audit):

    def __init__(self, neutron, vsd, cms_id, ignore_vsd_orphans=False):
        super(SecurityGroupAudit, self).__init__(cms_id, ignore_vsd_orphans)

        self.neutron = neutron
        self.vsd = vsd
        self.cms_id = cms_id

        self.audit_report = []
        self.cnt_in_sync = Counter()

    @TimeIt.timeit
    def audit_security_group_rules(self, domain, neutron_sg, vsd_pg_id,
                                   acl_template_type, is_l2,
                                   policygroup_id_fetcher):
        """Audit security group rules attached to a single domain


         Given a neutron securitygroup, domain and type of the acl_template:
            - Fetch securitygrouprules for securitygroup
            - Fetch acttemplateentries for specific domain and policygroup
                and acl_template_type, both egress and ingress
            - Compare rules with their corresponding entries
                - Identify the following discrepancies:
                    - VSD_ORPHAN
                    - NEUTRON_ORPHAN
                    - ENTITY_MISMATCH
                        - Compare:
                            - External ID
                            - remote_group_id
                            - direction
                            - ethertype
                            - port range
                            - protocol
                            - statefulness (part of securitygroup)
         Note: acl_template_type signals whether the securitygroup is for
              HARDWARE or SOFTWARE ports.
         """

        # Note that icmp rules represent both an ingress and egress acl entry
        # in VSD because VRS does not support stateful ICMP rules, that's why
        # they are added to both lists
        if (acl_template_type == ACL_TEMPLATE_SOFTWARE and
                neutron_sg['stateful']):
            # ICMP rules have both an ingress and egress acl entry
            # in VSD because VRS does not support stateful ICMP rules
            imcp_rules = [rule for rule in neutron_sg['security_group_rules']
                          if rule['protocol'] == 'icmp']
            egress_sg_rules = [rule
                               for rule in neutron_sg['security_group_rules']
                               if rule['direction'] == 'egress' and
                               rule['protocol'] != 'icmp'] + imcp_rules
            ingress_sg_rules = [rule
                                for rule in neutron_sg['security_group_rules']
                                if rule['direction'] == 'ingress' and
                                rule['protocol'] != 'icmp'] + imcp_rules
        else:
            egress_sg_rules = [rule
                               for rule in neutron_sg['security_group_rules']
                               if rule['direction'] == 'egress']
            ingress_sg_rules = [rule
                                for rule in neutron_sg['security_group_rules']
                                if rule['direction'] == 'ingress']

        ingress_acl_entries = list(self.vsd.get_ingress_acl_entries(
            by_domain=domain, by_policy_group_id=vsd_pg_id,
            cms_id=self.cms_id))
        egress_acl_entries = list(self.vsd.get_egress_acl_entries(
            by_domain=domain, by_policy_group_id=vsd_pg_id,
            cms_id=self.cms_id))

        matcher = SecurityGroupRuleAclTemplateEntryMatcher(
            is_stateful=neutron_sg['stateful'],
            acl_template_type=acl_template_type,
            is_l2_domain=is_l2,
            is_dhcp_managed=(domain.dhcp_managed == 'managed'
                             if is_l2 else False),
            policy_group_id=vsd_pg_id,
            policygroup_id_fetcher=policygroup_id_fetcher,
            enterprise_network_id_fetcher=self.vsd.get_enterprise_network_id)

        get_sg_ext_id = ((lambda r: 'hw:' + r['id'])
                         if acl_template_type == ACL_TEMPLATE_HARDWARE
                         else (lambda r: r['id']))

        INFO.h1('Auditing egress security group rules')
        in_sync_count = self.audit_entities(
            self.audit_report,
            egress_sg_rules,
            ingress_acl_entries,
            matcher,
            external_id_getter=get_sg_ext_id,
            report_tracked_entities=False)
        self.cnt_in_sync['ingress_acl_entry_templates'] += in_sync_count

        INFO.h1('Auditing ingress security group rules')
        in_sync_count = self.audit_entities(
            self.audit_report,
            ingress_sg_rules,
            egress_acl_entries,
            matcher,
            external_id_getter=get_sg_ext_id,
            report_tracked_entities=False)
        self.cnt_in_sync['egress_acl_entry_templates'] += in_sync_count

    @TimeIt.timeit
    def audit_security_groups(self):
        """Audit security groups attached to given router

        Given a router:
            - Calculate SG -> ports dict connected to this router
            - Calculate PG -> vports dict connected to corresponding l3domain
            - Fetch policygroup corresponding to every securitygroup
                - Compare securitygroup with policygroup
                    - Identify the following discrepancies
                        - VSD_ORPHAN
                        - NEUTRON_ORPHAN
                        - ENTITY_MISMATCH
                            - Compare:
                                - External ID
                                - Name
            - Call audit_security_group_rules for every security group
            - Compare set of sg_ports with set of pg_vports
        """
        for router_id, subnet_ids in six.iteritems(
                self._get_router_to_subnet_mapping()):
            if router_id:
                self.audit_l3_domain(router_id, subnet_ids)
            else:
                # when router_id is None we get the l2 domains
                self.audit_l2_domain(subnet_ids)

    def audit_l2_domain(self, subnet_ids):
        for subnet_id in subnet_ids:
            INFO.h1('Auditing security groups for subnet {}'
                    '.'.format(subnet_id))
            subnet = self.neutron.get_subnet(subnet_id)
            domain = self.vsd.get_l2domain(by_subnet=subnet)
            if domain is None:
                self.audit_report.append({
                    'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                    'entity_type': 'subnet',
                    'neutron_entity': subnet_id,
                    'vsd_entity': None,
                    'discrepancy_details': 'l2-subnet has no l2-domain'})
            else:
                self.audit_domain(domain, subnet['network_id'],
                                  [subnet_id], is_l2=True)

    def audit_l3_domain(self, router_id, subnet_ids):
        INFO.h1('Auditing security groups for router {}.'
                .format(router_id))
        if not subnet_ids:
            return
        domain = self.vsd.get_l3domain(by_neutron_id=router_id,
                                       vspk_filter=self.vspk_filter)
        if domain is None:
            self.audit_report.append({
                'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                'entity_type': 'router',
                'neutron_entity': router_id,
                'vsd_entity': None,
                'discrepancy_details': 'router has no l3-domain'})
        else:
            self.audit_domain(domain, router_id, subnet_ids, is_l2=False)

    def audit_security_group_ports(self, sg_to_ports, policygroup,
                                   securitygroup):
        """Compare set of sg_ports with set of pg_vports"""
        vports = self.vsd.get_vports(parent=policygroup)
        ports = sg_to_ports[securitygroup['id']][1]
        self.cnt_in_sync['vports'] += self.audit_entities(
            self.audit_report, ports, vports,
            SecurityGroupPortsPolicyGroupVportsMatcher(),
            report_tracked_entities=False)

    @staticmethod
    def get_sg_ext_id(sg):
        return ('hw:' + sg['id'] if sg['type'] == ACL_TEMPLATE_HARDWARE
                else sg['id'])

    def audit_domain(self, domain, network_id, subnet_ids, is_l2):
        sg_to_ports = self._get_sg_id_to_sg_and_ports_mapping(subnet_ids)
        # Calculate PG -> vports dict
        # vports is a fetcher on policygroup
        # filter out the PG_ALLOW_ALL
        _filter = "NOT(name BEGINSWITH '{}') AND {}".format(
            PG_ALLOW_ALL, self.vspk_filter)
        policygroups = list(self.vsd.get_policy_groups(
            domain, vspk_filter=_filter))
        policygroup_id_by_os_id = {self.strip_cms_id(pg.external_id): pg.id
                                   for pg in policygroups}

        def policygroup_id_fetcher(os_id):
            return policygroup_id_by_os_id.get(os_id)

        # Compare security groups with policy groups
        security_groups = [sg for (sg, _) in sg_to_ports.values()
                           if not sg['id'].startswith(PG_ALLOW_ALL)]

        def on_in_sync(policygroup, securitygroup):
            self.audit_security_group_ports(sg_to_ports, policygroup,
                                            securitygroup)
            self.audit_security_group_rules(domain, securitygroup,
                                            policygroup.id,
                                            securitygroup['type'], is_l2,
                                            policygroup_id_fetcher)
        nr_in_sync = self.audit_entities(
            self.audit_report,
            security_groups,
            policygroups,
            SecurityGroupPolicyGroupMatcher(),
            external_id_getter=self.get_sg_ext_id,
            on_in_sync=on_in_sync,
            report_tracked_entities=False)
        self.cnt_in_sync['policygroups'] += nr_in_sync

        # audit hardware policy group if needed
        if any(map(lambda x: x[0]['type'] == ACL_TEMPLATE_HARDWARE,
                   sg_to_ports.values())):
            my_report, my_counter = HardwarePGAudit(
                self.neutron, self.vsd,
                self.cms_id, self.ignore_vsd_orphans).audit(domain,
                                                            network_id)
            self.audit_report += my_report
            self.cnt_in_sync += my_counter

        # audit PG_ALLOW_ALL if needed
        for template_type in [ACL_TEMPLATE_HARDWARE, ACL_TEMPLATE_SOFTWARE]:
            is_hw = template_type == ACL_TEMPLATE_HARDWARE
            _, ports = (sg_to_ports.get('{}_{}'.format(PG_ALLOW_ALL,
                                                       template_type)) or
                        (None, []))
            vspk_filter = ("name BEGINSWITH '{}' and type IS '{}' and {}"
                           .format(PG_ALLOW_ALL, template_type,
                                   self.vspk_filter))
            pgs_allow_all = list(self.vsd.get_policy_groups(domain,
                                                            vspk_filter))
            cnt_in_sync = Counter()
            audit_report = []
            if len(pgs_allow_all) == 0:
                for port in ports:
                    audit_report.append({
                        'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                        'entity_type': 'Port',
                        'neutron_entity': port['id'],
                        'vsd_entity': domain.id,
                        'discrepancy_details': 'A Neutron port with '
                                               'port security disabled exists '
                                               'but there is no PG_ALLOW_ALL '
                                               'in its domain.'})
            elif len(pgs_allow_all) > 1:
                if self.ignore_vsd_orphans:
                    continue
                first = True
                for pg in pgs_allow_all:
                    if first:
                        first = False
                        continue
                    # else:
                    audit_report.append({
                        'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                        'entity_type': 'Policy Group',
                        'neutron_entity': None,
                        'vsd_entity': pg.id,
                        'discrepancy_details':
                            'Multiple {} PG_ALLOW_ALL policygroups are found '
                            'in VSD domain {}'.format(
                                'HW' if is_hw else 'SW', domain.id)})
            elif not ports:
                if self.ignore_vsd_orphans:
                    continue
                pg_allow_all = pgs_allow_all[0]
                self.audit_report.append({
                    'discrepancy_type': 'ORPHAN_VSD_ENTITY',
                    'entity_type': 'Policy Group',
                    'neutron_entity': None,
                    'vsd_entity': pg_allow_all.id,
                    'discrepancy_details':
                        'PG_ALLOW_ALL policygroup exists in VSD but there are '
                        'no neutron ports with port security disabled'})
            else:
                pg_allow_all = pgs_allow_all[0]
                audit_report, cnt_in_sync = PGAllowAllAudit(
                    self.neutron, self.vsd,
                    self.cms_id, self.ignore_vsd_orphans).audit(domain,
                                                                pg_allow_all,
                                                                ports)
            self.audit_report += audit_report
            self.cnt_in_sync += cnt_in_sync

    def _get_router_to_subnet_mapping(self):
        """Get router to subnet dict

        Map routerID -> set(subnetID,..)
        Note that None will be mapped to the l2 subnets
        """
        router_to_subnet = {}

        # l3 subnets
        for router in self.neutron.get_routers():
            # Get all router_interfaces attached to router
            filters = {'device_id': router['id'],
                       'device_owner': 'network:router_interface'}
            fields = ['fixed_ips']
            ports = self.neutron.get_ports(filters=filters, fields=fields)

            # Get set of subnet ids belonging to these router_interfaces
            router_to_subnet[router['id']] = {fix_ip['subnet_id']
                                              for port in ports
                                              for fix_ip in port['fixed_ips']}

        # l2 subnets
        public_networks = self.neutron.get_networks(
            filters={'router:external': True}, fields=['subnets'])
        public_subnets = {subnet
                          for network in public_networks
                          for subnet in network['subnets']}
        all_subnets = {subnet['id']
                       for subnet in self.neutron.get_subnets()}
        l3_subnets = (set.union(*six.itervalues(router_to_subnet))
                      if router_to_subnet else set())
        l2_subnets = all_subnets - l3_subnets - public_subnets
        router_to_subnet[None] = l2_subnets

        return router_to_subnet

    def _get_sg_id_to_sg_and_ports_mapping(self, subnet_ids):
        result = defaultdict(SGPortsTuple)

        # map the security group ids to ports
        ports_that_should_have_vport = filter(
            self.should_have_vport,
            self.neutron.get_ports_by_subnet_ids(subnet_ids))
        for port in ports_that_should_have_vport:
            # Handle normal security groups
            for sg_id in port['security_groups']:
                result[sg_id].ports.append(port)
            # Handle the case where PG_ALLOW_ALL is used
            if not port['port_security_enabled']:
                sg_type = (ACL_TEMPLATE_HARDWARE
                           if self.is_bound_baremetal_port(port)
                           else ACL_TEMPLATE_SOFTWARE)
                sg_id = PG_ALLOW_ALL + '_' + sg_type
                # Here we directly create the sg_group dictionary as it is
                # artificial anyway
                if result[sg_id].security_group is None:
                    result[sg_id].security_group = {'id': sg_id,
                                                    'type': sg_type}
                result[sg_id].ports.append(port)

        # fetch and add the security group objects
        for sg_id, sg_ports_tuple in six.iteritems(result):
            if sg_id.startswith(PG_ALLOW_ALL):
                continue
            sg = self.neutron.get_security_group(sg_id)
            sg['type'] = (ACL_TEMPLATE_HARDWARE
                          if any(self.is_bound_baremetal_port(port)
                                 for port in sg_ports_tuple.ports)
                          else ACL_TEMPLATE_SOFTWARE)
            sg_ports_tuple.security_group = sg

        # add the security groups used as remote sg but not attached to a port
        missing_sg_ids = {sg_rule['remote_group_id']
                          for (sg, _) in six.itervalues(result)
                          if 'security_group_rules' in sg
                          for sg_rule in sg['security_group_rules']
                          if sg_rule['remote_group_id'] is not None and
                          sg_rule['remote_group_id'] not in result}
        for remote_group_id in missing_sg_ids:
            remote_sg = self.neutron.get_security_group(remote_group_id)
            if not remote_sg:
                continue  # invalid
            remote_sg['type'] = ACL_TEMPLATE_SOFTWARE
            result[remote_group_id].security_group = remote_sg

        return result

    @staticmethod
    def is_normal_port(port):
        return port['binding:vnic_type'] == 'normal'

    @staticmethod
    def is_bound_baremetal_port(port):
        return (port['binding:vnic_type'] == 'baremetal' and
                port['binding:host_id'] and port['binding:profile'])

    @staticmethod
    def is_sriov_port(port):
        return port['binding:vnic_type'] in ['direct', 'direct-physical']

    @classmethod
    def should_have_vport(cls, port):
        if cls.is_normal_port(port):
            device_owner = port['device_owner']
            device_owner_prefix = Utils.get_env_var('OS_DEVICE_OWNER_PREFIX')
            return not (device_owner in AUTO_CREATE_PORT_OWNERS or
                        device_owner_prefix and device_owner.startswith(
                            device_owner_prefix))
        elif cls.is_sriov_port(port):
            # TODO(Tom) Add support for SRIOV ports
            WARN.h3("Port {} is a SRIOV port. SRIOV audit is not supported. "
                    "Orphan policygroups or orphan policygroup-vport "
                    "associations may be wrongly reported!")
        elif cls.is_bound_baremetal_port(port):
            return True
        else:
            return False

    def audit(self):
        self.audit_report = []

        # cnt_in_sync counts VSD entities that are in valid, elements are:
        #  - Number of acl entry templates related to PG_ALLOW_ALL
        #     'ingress_acl_entry_templates (PG_ALLOW_ALL)'
        #     'egress_acl_entry_templates (PG_ALLOW_ALL)'
        #
        #  - Number of vports in PG_ALLOW_ALL
        #     'vports (PG_ALLOW_ALL)'
        #
        #  - Number of acl entries related to default hardware block-all acl
        #     'egress_acl_entry_templates (hardware)'
        #
        #  - other acl entry templates
        #     'ingress_acl_entry_templates'
        #     'egress_acl_entry_templates'
        #
        #  - other policygroups
        #     'policygroups'
        #
        #  - other vports
        #     'vports'
        self.cnt_in_sync = Counter()

        self.audit_security_groups()
        return self.audit_report, self.cnt_in_sync
