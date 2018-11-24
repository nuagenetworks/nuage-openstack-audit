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

from nuage_openstack_audit.utils.timeit import TimeIt


class OSCredentials(object):
    def __init__(self, auth_url, username, password, project_name,
                 identity_api_version,
                 user_domain_id=None, project_domain_id=None):
        self.auth_url = auth_url
        self.username = username
        self.password = password
        self.project_name = project_name
        self.identity_api_version = identity_api_version
        if identity_api_version == 3:
            self.auth_url = self.assure_endswith(self.auth_url, '/v3')
            self.user_domain_id = user_domain_id
            self.project_domain_id = project_domain_id
        else:
            self.auth_url = self.assure_endswith(self.auth_url, '/v2.0')

    @staticmethod
    def assure_endswith(url, endswith):
        return url if url.endswith(endswith) else (url + endswith)


class KeystoneClient(object):
    def __init__(self):
        self.client = None
        self.session = None

    def authenticate(self, credentials, init_client=True):
        from keystoneauth1.exceptions.auth import AuthorizationFailure \
            as KeyStoneAuthorizationFailure
        from keystoneauth1.identity import v3 as keystone_v3
        from keystoneauth1 import session as keystone_session

        from keystoneclient.v2_0 import client as keystone_v2_client
        from keystoneclient.v3 import client as keystone_client

        from osc_lib.exceptions import AuthorizationFailure
        from osc_lib.exceptions import Unauthorized

        try:
            if credentials.identity_api_version == 3:
                auth = keystone_v3.Password(
                    auth_url=credentials.auth_url,
                    username=credentials.username,
                    password=credentials.password,
                    project_name=credentials.project_name,
                    user_domain_id=credentials.user_domain_id,
                    project_domain_id=credentials.project_domain_id)

                self.session = keystone_session.Session(auth=auth)
                if init_client:
                    self.client = keystone_client.Client(session=self.session)
            else:
                if init_client:
                    self.client = keystone_v2_client.Client(
                        username=credentials.username,
                        password=credentials.password,
                        tenant_name=credentials.project_name,
                        auth_url=credentials.auth_url)
            return self

        except (AuthorizationFailure, KeyStoneAuthorizationFailure,
                Unauthorized) as e:
            raise EnvironmentError('Authentication failure: ' + str(e))


class NeutronClient(object):
    def __init__(self):
        self.client = None

    def authenticate(self, credentials):
        from neutronclient.neutron import client as neutron_client
        from neutronclient.v2_0 import client as neutron_client_v2

        keystone_client = KeystoneClient().authenticate(credentials,
                                                        init_client=False)
        self.client = (
            neutron_client.Client(
                api_version='2.0',
                session=keystone_client.session) if keystone_client.session
            else neutron_client_v2.Client(
                username=credentials.username,
                password=credentials.password,
                tenant_name=credentials.project_name,
                auth_url=credentials.auth_url))
        return self

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
