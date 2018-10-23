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

import requests

from keystoneauth1.exceptions.auth import AuthorizationFailure \
    as KeyStoneAuthorizationFailure
from keystoneauth1.identity import v3 as keystone_v3
from keystoneauth1 import session as keystone_session

from keystoneclient.v2_0 import client as keystone_v2_client
from keystoneclient.v3 import client as keystone_client

import neutronclient.common.exceptions as neutron_exceptions
from neutronclient.neutron import client as neutron_client
from neutronclient.v2_0 import client as neutron_client_v2

from osc_lib.exceptions import AuthorizationFailure
from osc_lib.exceptions import Unauthorized

from nuage_openstack_audit.utils import logger
from nuage_openstack_audit.utils.timeit import TimeIt
from nuage_openstack_audit.utils.utils import get_env_var

# suppress warning
requests.packages.urllib3.disable_warnings()

LOG = logger.get_logger()


class OSCredentials(object):
    def __init__(self):
        self.auth_url = get_env_var('OS_AUTH_URL')
        self.username = get_env_var('OS_USERNAME')
        self.project_name = get_env_var(
            'OS_PROJECT_NAME', get_env_var('OS_TENANT_NAME'))
        self.password = get_env_var('OS_PASSWORD')
        self.identity_api_version = int(
            get_env_var('OS_IDENTITY_API_VERSION', 3))
        if self.is_v3():
            self.auth_url = self.assure_endswith(self.auth_url, '/v3')
            self.user_domain_id = get_env_var('OS_USER_DOMAIN_ID')
            self.project_domain_id = get_env_var('OS_PROJECT_DOMAIN_ID')
        else:
            self.auth_url = self.assure_endswith(self.auth_url, '/v2.0')

    def is_v3(self):
        return self.identity_api_version == 3

    @staticmethod
    def assure_endswith(url, endswith):
        if not url.endswith(endswith):
            LOG.info('... Expanding %s to %s', url, url + endswith)
            url += endswith
        return url


class Keystone(object):

    def __init__(self, session=None, credentials=None):
        try:
            self.authentication_success = False
            self.authentication_failure = None
            if session:
                self.client = keystone_client.Client(session=session)
            else:
                self.credentials = credentials
                self.client = keystone_v2_client.Client(
                    username=credentials.username,
                    password=credentials.password,
                    tenant_name=credentials.project_name,
                    auth_url=credentials.auth_url)

            self.authentication_success = True
        except (AuthorizationFailure, KeyStoneAuthorizationFailure,
                Unauthorized) as e:
            self.authentication_failure = e

    def get_token(self):
        return self.client.get_raw_token_from_identity_service(
            auth_url=self.credentials.auth_url,
            username=self.credentials.username,
            password=self.credentials.password,
            tenant_name=self.credentials.project_name)['token']


class Neutron(object):
    def __init__(self, session=None, credentials=None):
        if session:
            self.client = neutron_client.Client('2.0', session=session)
        else:
            self.client = neutron_client_v2.Client(
                username=credentials.username,
                password=credentials.password,
                tenant_name=credentials.project_name,
                auth_url=credentials.auth_url)

    def get_routers(self):
        return self.client.list_routers()['routers']

    def create_router(self, name):
        return self.client.create_router(
            {'router': {
                'name': name}})['router']

    def delete_router(self, router):
        try:
            self.client.delete_router(router['id'])
        except neutron_exceptions.Conflict:
            print('router %s could not be deleted '
                  'as of conflict error.' % router['id'])

    @TimeIt.timeit
    def get_firewalls(self):
        return self.client.list_firewalls()['firewalls']

    @TimeIt.timeit
    def get_firewall_policies(self):
        return self.client.list_firewall_policies()['firewall_policies']

    @TimeIt.timeit
    def get_firewall_rules(self):
        return self.client.list_firewall_rules()['firewall_rules']

    def get_firewall_rules_by_policy(self, policy_id):
        return self.client.list_firewall_rules(
            firewall_policy_id=policy_id)['firewall_rules']

    def create_firewall_rule(self, protocol='tcp', action='allow',
                             enabled=True):
        return self.client.create_firewall_rule(
            {'firewall_rule': {
                'protocol': protocol,
                'action': action,
                'enabled': enabled}})['firewall_rule']

    def delete_firewall_rule(self, fw_rule):
        self.client.delete_firewall_rule(fw_rule['id'])

    def create_firewall_policy(self, name, rules):
        return self.client.create_firewall_policy(
            {'firewall_policy': {
                'name': name,
                'firewall_rules': rules}})['firewall_policy']

    def delete_firewall_policy(self, policy):
        self.client.delete_firewall_policy(policy['id'])

    def create_firewall(self, policy, router):
        return self.client.create_firewall(
            {'firewall': {
                'router_ids': [router['id']],
                'firewall_policy_id': policy['id']}})['firewall']

    def delete_firewall(self, fw):
        self.client.delete_firewall(fw['id'])


class OSClient(object):
    def __init__(self):
        self._me = OSCredentials()
        self._v3 = self._me.is_v3()
        self._keystone = None
        self._neutron = None
        self._authenticated = None
        self._session = None

        self.authenticate()

    def authenticated(self):
        return self._authenticated

    def authenticate(self):
        if self._authenticated is None:
            if self._v3:
                auth = keystone_v3.Password(
                    auth_url=self._me.auth_url,
                    username=self._me.username,
                    password=self._me.password,
                    project_name=self._me.project_name,
                    user_domain_id=self._me.user_domain_id,
                    project_domain_id=self._me.project_domain_id)

                # session.Session(auth=auth, verify='/path/to/ca.cert')
                self._session = keystone_session.Session(auth=auth,
                                                         verify=False)

            self._authenticated = self.keystone().authentication_success
            if not self._authenticated:
                LOG.error('ERROR: ' +
                          str(self.keystone().authentication_failure))

    def keystone(self):
        if not self._keystone:
            if self._v3:
                LOG.debug('Authenticating with keystone v3...')
                self._keystone = Keystone(self._session)
            else:
                LOG.debug('Authenticating with keystone v2...')
                self._keystone = Keystone(credentials=self._me)
        return self._keystone

    def neutron(self):
        if not self._neutron:
            if self._v3:
                self._neutron = Neutron(self._session)
            else:
                self._neutron = Neutron(credentials=self._me)
        return self._neutron
