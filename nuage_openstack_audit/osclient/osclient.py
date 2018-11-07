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

from nuage_openstack_audit.utils import logger
from nuage_openstack_audit.utils.timeit import TimeIt
from nuage_openstack_audit.utils.utils import Utils

LOG = logger.get_logger()


class OSCredentials(object):
    def __init__(self):
        self.auth_url = Utils.get_env_var('OS_AUTH_URL')
        self.username = Utils.get_env_var('OS_USERNAME')
        self.project_name = Utils.get_env_var(
            'OS_PROJECT_NAME', Utils.get_env_var('OS_TENANT_NAME', ''))
        if not self.project_name:
            Utils.env_error('OS_PROJECT_NAME nor OS_TENANT_NAME '
                            'is defined. Please set either of both.')
        self.password = Utils.get_env_var('OS_PASSWORD')
        self.identity_api_version = int(
            Utils.get_env_var('OS_IDENTITY_API_VERSION', 3))
        if self.v3():
            self.auth_url = self.assure_endswith(self.auth_url, '/v3')
            self.user_domain_id = Utils.get_env_var('OS_USER_DOMAIN_ID')
            self.project_domain_id = Utils.get_env_var('OS_PROJECT_DOMAIN_ID')
        else:
            self.auth_url = self.assure_endswith(self.auth_url, '/v2.0')

    def v3(self):
        return self.identity_api_version == 3

    @staticmethod
    def assure_endswith(url, endswith):
        if not url.endswith(endswith):
            LOG.info('... Expanding %s to %s', url, url + endswith)
            url += endswith
        return url


class Keystone(object):
    def __init__(self, credentials):
        from keystoneauth1.exceptions.auth import AuthorizationFailure \
            as KeyStoneAuthorizationFailure
        from keystoneauth1.identity import v3 as keystone_v3
        from keystoneauth1 import session as keystone_session

        from keystoneclient.v2_0 import client as keystone_v2_client
        from keystoneclient.v3 import client as keystone_client

        from osc_lib.exceptions import AuthorizationFailure
        from osc_lib.exceptions import Unauthorized

        self.credentials = credentials
        try:
            if credentials.v3():
                auth = keystone_v3.Password(
                    auth_url=credentials.auth_url,
                    username=credentials.username,
                    password=credentials.password,
                    project_name=credentials.project_name,
                    user_domain_id=credentials.user_domain_id,
                    project_domain_id=credentials.project_domain_id)

                self.session = keystone_session.Session(auth=auth)
                self.client = keystone_client.Client(session=self.session)
                self.v3 = True
            else:
                self.client = keystone_v2_client.Client(
                    username=credentials.username,
                    password=credentials.password,
                    tenant_name=credentials.project_name,
                    auth_url=credentials.auth_url)
                self.v3 = False

        except (AuthorizationFailure, KeyStoneAuthorizationFailure,
                Unauthorized) as e:
            Utils.env_error('Authentication failure: ' + str(e))


class Neutron(object):
    def __init__(self, keystone):
        from neutronclient.neutron import client as neutron_client
        from neutronclient.v2_0 import client as neutron_client_v2

        if keystone.v3:
            self.client = neutron_client.Client(
                '2.0', session=keystone.session)
        else:
            self.client = neutron_client_v2.Client(
                username=keystone.credentials.username,
                password=keystone.credentials.password,
                tenant_name=keystone.credentials.project_name,
                auth_url=keystone.credentials.auth_url)

    @TimeIt.timeit
    def get_firewalls(self):
        return self.client.list_firewalls()['firewalls']

    @TimeIt.timeit
    def get_firewall_policies(self):
        return self.client.list_firewall_policies()['firewall_policies']

    @TimeIt.timeit
    def get_firewall_rules(self):
        return self.client.list_firewall_rules()['firewall_rules']

    @TimeIt.timeit
    def get_routers(self):
        return self.client.list_routers()['routers']

    @TimeIt.timeit
    def get_networks(self, filters=None, fields=None):
        kwargs = {}
        if filters:
            kwargs = filters
        if fields:
            kwargs['fields'] = fields
        return self.client.list_networks(**kwargs)['networks']

    @TimeIt.timeit
    def get_subnets(self):
        return self.client.list_subnets()['subnets']

    @TimeIt.timeit
    def get_ports(self, filters=None, fields=None):
        kwargs = {}
        if filters:
            kwargs = filters
        if fields:
            kwargs['fields'] = fields
        return self.client.list_ports(**kwargs)['ports']

    @TimeIt.timeit
    def get_security_group(self, sg_id):
        return self.client.show_security_group(sg_id)['security_group']
