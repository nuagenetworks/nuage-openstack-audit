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
import sqlalchemy
from sqlalchemy.ext.automap import automap_base as sqlalchemy_automap
from sqlalchemy.orm import sessionmaker as sqlalchemy_sessionmaker
from urlparse import urlparse

import neutronclient.common.exceptions as neutron_exceptions
from nuage_openstack_audit.osclient.osclient import NeutronClient
from nuage_openstack_audit.utils.logger import Reporter

USER = Reporter('USER')


class NeutronTopology(object):
    """Set up and tear down a neutron topology"""

    teardown_action_stack = []

    def __init__(self):
        self.neutron = NeutronClient()

        # Counter counts the following things:
        #  - Number of security groups that also have a VSD representation
        #    i.e having a rule, used as remote in a rule, ..
        #     'sgs'
        #
        #  - Number of ingress / egress security group rules
        #     'sg_rules_ingress'
        #     'sg_rules_egress'
        #
        #  - Number of security groups used as a remote group in a rule
        #     'remote_sgs'
        #
        #  - Number of rules in security groups that are used as a remote group
        #     'sg_rules_remote'
        #
        #  - Number of ports with / without security group / port sec disabled
        #     'ports_sg'
        #     'ports_no_security'
        #     'ports_security_disabled'
        self.counter = Counter()
        self.neutron_db_classes = None
        self.neutron_session_class = None

    def authenticate(self, credentials, db_access=False):
        self.neutron.authenticate(credentials)

        # Neutron database
        if db_access:
            auth_url = credentials.auth_url
            devstack_ip_with_port = urlparse(auth_url).netloc
            devstack_ip = devstack_ip_with_port.split(':')[0]
            engine_str = ('mysql+pymysql://root:admin@{}/neutron?charset=utf8'
                          .format(devstack_ip))
            engine = sqlalchemy.create_engine(engine_str, echo=False,
                                              encoding='utf-8')
            automap_base = sqlalchemy_automap()
            automap_base.prepare(engine, reflect=True)
            self.neutron_db_classes = automap_base.classes
            self.neutron_session_class = sqlalchemy_sessionmaker(bind=engine)

    def enable_port_security_in_db(self, port_id):
        """Enable port_security_enabled by direct access to the neutron db"""
        self._update_portsecuritybindings_in_db(port_id, 1)

    def disable_port_security_in_db(self, port_id):
        """Disable port_security_enabled by direct access to the neutron db"""
        self._update_portsecuritybindings_in_db(port_id, 0)

    def _update_portsecuritybindings_in_db(self, port_id, new_value):
        assert new_value in [0, 1]
        assert self.neutron_session_class is not None
        session = self.neutron_session_class()
        db_instance = session.query(
            self.neutron_db_classes.portsecuritybindings).get(port_id)
        db_instance.port_security_enabled = new_value
        session.commit()

    def is_dhcp_agent_enabled(self):
        return self.neutron.is_dhcp_agent_enabled()

    def teardown(self):
        """Cleanup of created topology"""
        USER.report('=== Teardown of OpenStack test topology ===')
        while self.teardown_action_stack:
            action = self.teardown_action_stack.pop()
            try:
                action()
            except Exception:
                pass
        self.counter = Counter()

    def create_subnet_l2(self, *args, **kwargs):
        """A subnet that will not be attached to a router"""
        self.counter['domains'] += 1  # results in l2 domain
        return self._create_subnet(*args, **kwargs)

    def create_subnet_l3(self, *args, **kwargs):
        """A subnet that will be attached to a router"""
        return self._create_subnet(*args, **kwargs)

    def create_security_group_used(self, *args, **kwargs):
        """A security group that has a representation on vsd"""
        # Creating a sg gives rise to an implicit IPv4 and IPv6 rule
        self.counter += Counter(sgs=1, sg_rules_egress=2)
        return self._create_security_group(*args, **kwargs)

    def create_security_group_unused(self, *args, **kwargs):
        """A security group that has no representation on vsd"""
        # No counters are increased since there is no vsd representation
        return self._create_security_group(*args, **kwargs)

    def create_security_group_remote_used(self, *args, **kwargs):
        """A used security group referenced as remote group in a rule"""
        self.counter += Counter(remote_sgs=1, sg_rules_remote=2)
        return self.create_security_group_used(*args, **kwargs)

    def create_security_group_rule_stateful(self, *args, **kwargs):
        """A security group rule that is stateful"""
        return self._create_security_group_rule_impl(True, *args, **kwargs)

    def create_security_group_rule_stateless(self, *args, **kwargs):
        """A security group rule that is stateless"""
        return self._create_security_group_rule_impl(False, *args, **kwargs)

    def _create_security_group_rule_impl(self, stateful, *args, **kwargs):
        assert kwargs.get('direction') in ['ingress', 'egress']
        assert kwargs.get('protocol')

        if kwargs['direction'] == 'ingress':
            self.counter += Counter(sg_rules_ingress=1)
            if stateful and kwargs['protocol'] == 'icmp':
                # Reflexive rule added to VSD
                self.counter += Counter(sg_rules_egress=1)
        else:
            self.counter += Counter(sg_rules_egress=1)
            if stateful and kwargs['protocol'] == 'icmp':
                # Reflexive rule added to VSD
                self.counter += Counter(sg_rules_ingress=1)

        return self._create_security_group_rule(*args, **kwargs)

    def create_port(self, *args, **kwargs):
        if (kwargs.get('port_security_enabled', True) and
                kwargs.get('security_groups') != []):
            self.counter += Counter(ports_sg=1)
        else:
            if not kwargs.get('port_security_enabled', True):
                self.counter += Counter(ports_security_disabled=1)
            self.counter += Counter(ports_no_security=1)

        return self._create_port(*args, **kwargs)

    def create_router(self, name, **kwargs):
        kwargs['name'] = name
        router = self.neutron.client.create_router(
            {'router': kwargs})['router']
        router_id = router['id']
        self.teardown_action_stack.append(
            lambda: self._delete_router(router_id))
        self.counter['domains'] += 1
        return router

    def _delete_router(self, router_id):
        try:
            self.neutron.client.delete_router(router_id)
        except neutron_exceptions.Conflict:
            print('router %s could not be deleted '
                  'as of conflict error.' % router_id)

    def create_network(self, name, admin_state_up=True, **kwargs):
        kwargs['name'] = name
        kwargs['admin_state_up'] = admin_state_up
        body = {
            'network': kwargs
        }
        network = self.neutron.client.create_network(
            body)['network']
        network_id = network['id']
        self.teardown_action_stack.append(
            lambda: self._delete_network(network_id))
        return network

    def _delete_network(self, network_id):
        self.neutron.client.delete_network(network_id)

    def _create_subnet(self, network_id, ip_version, cidr, project_id=None):
        kwargs = {"subnet": {"network_id": network_id,
                             "ip_version": ip_version, "cidr": cidr}}
        if project_id:
            kwargs['subnet']['project_id'] = project_id
        subnet = self.neutron.client.create_subnet(kwargs)['subnet']
        subnet_id = subnet['id']
        self.teardown_action_stack.append(
            lambda: self._delete_subnet(subnet_id))
        return subnet

    def _delete_subnet(self, subnet_id):
        self.neutron.client.delete_subnet(subnet_id)

    def _create_port(self, network, project_id=None, **kwargs):
        body = kwargs or {}
        body['network_id'] = network['id']
        if project_id:
            body['project_id'] = project_id
        body = {'port': body}
        port = self.neutron.client.create_port(body)['port']
        port_id = port['id']
        self.teardown_action_stack.append(lambda: self._delete_port(port_id))
        return port

    def _delete_port(self, port_id):
        self.neutron.client.delete_port(port_id)

    def create_router_interface(self, router_id, subnet_id, project_id=None):
        body = {
            'subnet_id': subnet_id,
            'project_id': project_id
        }
        ri = self.neutron.client.add_interface_router(router_id, body)
        self.teardown_action_stack.append(
            lambda: self._delete_router_interface(router_id, subnet_id))
        return ri

    def _delete_router_interface(self, router_id, subnet_id):
        body = {
            'subnet_id': subnet_id
        }
        return self.neutron.client.remove_interface_router(router_id, body)

    def create_firewall_rule(self, protocol='tcp', action='allow',
                             enabled=True, **kwargs):
        kwargs['protocol'] = protocol
        kwargs['action'] = action
        kwargs['enabled'] = enabled
        rule = self.neutron.client.create_firewall_rule(
            {'firewall_rule': kwargs})['firewall_rule']
        rule_id = rule['id']
        self.teardown_action_stack.append(
            lambda: self._delete_firewall_rule(rule_id))
        return rule

    def _delete_firewall_rule(self, fw_rule_id):
        self.neutron.client.delete_firewall_rule(fw_rule_id)

    def create_firewall_policy(self, name, rules, **kwargs):
        kwargs['name'] = name
        kwargs['firewall_rules'] = rules
        policy = self.neutron.client.create_firewall_policy(
            {'firewall_policy': kwargs})['firewall_policy']
        policy_id = policy['id']
        self.teardown_action_stack.append(
            lambda: self._delete_firewall_policy(policy_id))
        return policy

    def _delete_firewall_policy(self, policy_id):
        self.neutron.client.delete_firewall_policy(policy_id)

    def create_firewall(self, policy, router, admin_state_up=True, **kwargs):
        kwargs['router_ids'] = [router['id']]
        kwargs['firewall_policy_id'] = policy['id']
        kwargs['admin_state_up'] = admin_state_up
        firewall = self.neutron.client.create_firewall(
            {'firewall': kwargs})['firewall']
        firewall_id = firewall['id']
        self.teardown_action_stack.append(
            lambda: self._delete_firewall(firewall_id))
        return firewall

    def _delete_firewall(self, firewall_id):
        self.neutron.client.delete_firewall(firewall_id)

    def _create_security_group(self, **kwargs):
        sg = self.neutron.client.create_security_group(
            {"security_group": kwargs})['security_group']
        sg_id = sg['id']
        self.teardown_action_stack.append(
            lambda: self._delete_security_group(sg_id))
        return sg

    def _delete_security_group(self, sg_id):
        self.neutron.client.delete_security_group(sg_id)

    def _create_security_group_rule(self, *_, **kwargs):
        sg_rule = self.neutron.client.create_security_group_rule(
            {"security_group_rule": kwargs})['security_group_rule']
        sg_rule_id = sg_rule['id']
        self.teardown_action_stack.append(
            lambda: self._delete_security_group_rule(sg_rule_id))
        return sg_rule

    def _delete_security_group_rule(self, rule_id):
        self.neutron.client.delete_security_group_rule(rule_id)
