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

from re import search

from nuage_openstack_audit.vsdclient.common.vspk_helper import VspkHelper
from nuage_openstack_audit.vsdclient.resources.fwaas_mixin import FWaaSMixin
from nuage_openstack_audit.vsdclient.resources.security_groups_mixin \
    import SecurityGroupsMixin


class VsdCredentials(object):

    def __init__(self, vsd_server, user, password, enterprise, base_uri):
        self.vsd_server = vsd_server
        self.user = user
        self.password = password
        self.enterprise = enterprise
        self.base_uri = base_uri
        self.api_version = '{}'.format(search(r'(v\d+_?\d*$)',
                                              base_uri).group())

    def report(self, log):
        obfuscated_me = vars(self).copy()
        obfuscated_me['password'] = '***'

        log.report('VsdCredentials')
        log.pprint(obfuscated_me)


class VsdClient(FWaaSMixin, SecurityGroupsMixin):

    def __init__(self, cms_id):
        self.vspk_helper = VspkHelper(cms_id)

        # Init all base classes here
        FWaaSMixin.__init__(self, self.vspk_helper)
        SecurityGroupsMixin.__init__(self, self.vspk_helper)

    def authenticate(self, credentials):
        self.vspk_helper.authenticate(credentials)
        return self
