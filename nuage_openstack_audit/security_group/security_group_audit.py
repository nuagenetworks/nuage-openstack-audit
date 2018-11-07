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
from collections import defaultdict

import six

from nuage_openstack_audit.audit import Audit
from nuage_openstack_audit.utils import logger
from nuage_openstack_audit.utils.timeit import TimeIt
from nuage_openstack_audit.security_group.modules.pg_for_less \
    import PGForLessAudit
from nuage_openstack_audit.security_group.modules.hardware \
    import HardwarePGAudit
from nuage_openstack_audit.security_group.security_group_matchers \
    import SecurityGroupRuleAclTemplateEntryMatcher
from nuage_openstack_audit.security_group.security_group_matchers \
    import SecurityGroupPolicyGroupMatcher
from nuage_openstack_audit.security_group.security_group_matchers \
    import SecurityGroupPortsPolicyGroupVportsMatcher

from nuage_openstack_audit.utils.utils import Utils


INFO = logger.Reporter()
WARN = logger.Reporter(level='WARN')

PG_FOR_LESS_SECURITY = 'PG_FOR_LESS_SECURITY'
ACL_TEMPLATE_SOFTWARE = 'SOFTWARE'
ACL_TEMPLATE_HARDWARE = 'HARDWARE'

AUTO_CREATE_PORT_OWNERS = ['network:router_interface',
                           'network:router_gateway', 'network:floatingip',
                           'nuage:vip', 'compute:ironic', 'network:dhcp:nuage']


class SecurityGroupAudit(Audit):

    def __init__(self, neutron, vsd, cms_id):
        super(SecurityGroupAudit, self).__init__(cms_id)

        self.neutron = neutron
        self.vsd = vsd
        self.cms_id = cms_id

        self.audit_report = []
        self.cnt_in_sync = 0

    @TimeIt.timeit
    def audit_security_group_rules(self, domain, neutron_sg, vsd_pg_id,
                                   acl_template_type, is_l2):
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
                            - statefulnes (part of securitygroup)
         Note: acl_template_type signals whether the securitygroup is for
              HARDWARE ( or SOFTWARE ports.
         """

        # Note that icmp rules represent both an ingress and egress acl entry
        # in VSD because VRS does not support stateful ICMP rules, that's why
        # they are added to both lists
        if acl_template_type == ACL_TEMPLATE_SOFTWARE:
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

        ingress_acl_entries = self.vsd.get_ingress_acl_entries(
            by_domain=domain, by_policy_group_id=vsd_pg_id,
            cms_id=self.cms_id)
        egress_acl_entries = self.vsd.get_egress_acl_entries(
            by_domain=domain, by_policy_group_id=vsd_pg_id,
            cms_id=self.cms_id)

        matcher = SecurityGroupRuleAclTemplateEntryMatcher(
            is_stateful=neutron_sg['stateful'],
            acl_template_type=acl_template_type,
            is_l2_domain=is_l2,
            is_dhcp_managed=(domain.dhcp_managed == 'managed'
                             if is_l2 else False),
            policy_group_id=vsd_pg_id)

        get_sg_ext_id = ((lambda r: 'hw:' + r['id'])
                         if acl_template_type == ACL_TEMPLATE_HARDWARE
                         else (lambda r: r['id']))

        INFO.h1('Auditing egress security group rules')
        self.cnt_in_sync += self.audit_entities(
            self.audit_report,
            egress_sg_rules,
            ingress_acl_entries,
            matcher,
            external_id_getter=get_sg_ext_id)

        INFO.h1('Auditing ingress security group rules')
        self.cnt_in_sync += self.audit_entities(
            self.audit_report,
            ingress_sg_rules,
            egress_acl_entries,
            matcher,
            external_id_getter=get_sg_ext_id)

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
            domain = self.vsd.get_l2domain(by_neutron_id=subnet_id,
                                           vspk_filter=self.vspk_filter)
            if domain is None:
                self.audit_report.append({
                    'discrepancy_type': 'ORPHAN_NEUTRON_ENTITY',
                    'entity_type': 'subnet',
                    'neutron_entity': subnet_id,
                    'vsd_entity': None,
                    'discrepancy_details': 'l2-subnet has no '
                                           'l2-domain'})
            else:
                self.audit_domain(domain, subnet_id, [subnet_id], is_l2=True)

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
        self.cnt_in_sync += self.audit_entities(
            self.audit_report, ports, vports,
            SecurityGroupPortsPolicyGroupVportsMatcher())

    @staticmethod
    def get_sg_ext_id(sg):
        return ('hw:' + sg['id']
                if sg['type'] == ACL_TEMPLATE_HARDWARE else sg['id'])

    def audit_domain(self, domain, os_id, subnet_ids, is_l2):
        sg_to_ports = self._get_sg_to_ports_mapping(subnet_ids)
        # Calculate PG -> vports dict
        # vports is a fetcher on policygroup
        # filter out the defaultPG_ for SRIOV
        policygroups = self.vsd.get_policy_groups(
            domain, vspk_filter="not(name BEGINSWITH 'defaultPG-' or name "
                                "BEGINSWITH 'PG_FOR_LESS')" + " and " +
                                self.vspk_filter)
        # Compare security groups with policy groups
        security_groups = [sg for (sg, _) in sg_to_ports.values()
                           if not sg['id'].startswith(PG_FOR_LESS_SECURITY)]

        def on_in_sync(policygroup, securitygroup):
            self.audit_security_group_ports(sg_to_ports, policygroup,
                                            securitygroup)
            self.audit_security_group_rules(domain, securitygroup,
                                            policygroup.id,
                                            securitygroup['type'], is_l2)
        nr_in_sync = self.audit_entities(
            self.audit_report,
            security_groups,
            policygroups,
            SecurityGroupPolicyGroupMatcher(),
            external_id_getter=self.get_sg_ext_id,
            on_in_sync=on_in_sync)
        self.cnt_in_sync += nr_in_sync

        # audit hardware policy group if needed
        if any(map(lambda x: x[0]['type'] == ACL_TEMPLATE_HARDWARE,
                   sg_to_ports.values())):
            my_report, my_cnt = HardwarePGAudit(
                self.neutron, self.vsd, self.cms_id).audit(domain, os_id)
            self.audit_report += my_report
            self.cnt_in_sync += my_cnt

        # audit PG_FOR_LESS_SECURITY if needed
        for template_type in [ACL_TEMPLATE_HARDWARE, ACL_TEMPLATE_SOFTWARE]:
            _, ports = (sg_to_ports.get('{}_{}'.format(PG_FOR_LESS_SECURITY,
                                                       template_type)) or
                        (None, None))
            if ports:
                vspk_filter = ("name BEGINSWITH 'PG_FOR_LESS' and "
                               "type IS '{}'".format(template_type) +
                               " and " + self.vspk_filter)
                policygroups = list(self.vsd.get_policy_groups(domain,
                                                               vspk_filter))
                audit_report, cnt_in_sync = PGForLessAudit(
                    self.neutron, self.vsd, self.cms_id).audit(domain,
                                                               policygroups,
                                                               ports)
                self.audit_report += audit_report
                self.cnt_in_sync += cnt_in_sync

    def _get_router_to_subnet_mapping(self):
        """
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
        router_to_subnet[None] = (all_subnets -
                                  set.union(*router_to_subnet.itervalues()) -
                                  public_subnets)

        return router_to_subnet

    def _get_sg_to_ports_mapping(self, subnet_ids):
        subnet_filter = ['subnet_id={}'.format(my_id) for my_id in subnet_ids]
        ports = self.neutron.get_ports({'fixed_ips': subnet_filter})
        # Calculate SG -> Ports dict
        sg_id_to_ports = defaultdict(list)
        sg_to_ports = {}
        for port in ports:
            if not self.should_have_vport(port):
                continue
            # Handle normal security groups
            for sg in port['security_groups']:
                sg_id_to_ports[sg].append(port)
            # Handle the case where PG_FOR_LESS_SECURITY is used
            if not port['port_security_enabled']:
                sg_type = (ACL_TEMPLATE_HARDWARE if
                           (port['binding:vnic_type'] == 'baremetal' and
                            port['binding:host_id'] and
                            port['binding:profile']) else
                           ACL_TEMPLATE_SOFTWARE)
                sg_id = PG_FOR_LESS_SECURITY + '_' + sg_type
                # Here we directly create the sg_group dictionary as it is
                # artificial anyway
                if sg_to_ports.get(sg_id):
                    _, ports = sg_to_ports[sg_id]
                    ports.append(port)
                else:
                    sg = {'id': sg_id, 'type': sg_type}
                    sg_to_ports[sg_id] = (sg, [port])
        for sg_id, ports in six.iteritems(sg_id_to_ports):
            sg = self.neutron.get_security_group(sg_id)
            sg_type = (ACL_TEMPLATE_HARDWARE if any(map(
                lambda x: x['binding:vnic_type'] == 'baremetal' and
                x['binding:host_id'] and x['binding:profile'], ports)) else
                ACL_TEMPLATE_SOFTWARE)
            sg['type'] = sg_type
            sg_to_ports[sg_id] = (sg, ports)
        return sg_to_ports

    @staticmethod
    def should_have_vport(port):
        if port['binding:vnic_type'] == 'normal':
            device_owner = port['device_owner']
            return not (device_owner in AUTO_CREATE_PORT_OWNERS or
                        device_owner.startswith(tuple(
                            Utils.get_env_var('OS_DEVICE_OWNER_PREFIX', ''))))
        elif port['binding:vnic_type'] in ['direct', 'direct-physical']:
            # TODO Add support for SRIOV ports
            WARN.h3("Port {} is a SRIOV port. SRIOV audit is not supported. "
                    "Orphan policygroups or orphan policygroup-vport "
                    "associations may be wrongly reported!")
        elif port['binding:vnic_type'] == 'baremetal':
            return port['binding:host_id'] and port['binding:profile']
        else:
            return False  # Default: no vport on VSD

    def audit(self):
        self.audit_report = []
        self.cnt_in_sync = 0
        self.audit_security_groups()
        return self.audit_report, self.cnt_in_sync
