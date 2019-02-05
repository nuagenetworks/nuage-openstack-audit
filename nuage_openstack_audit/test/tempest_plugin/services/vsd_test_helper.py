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

from tempest import config

from nuage_openstack_audit.vsdclient.vsdclient import VsdClient
from nuage_openstack_audit.vsdclient.vsdclient import VsdCredentials

VSD_CONF = config.CONF.nuage_openstack_audit
VSD_CREDENTIALS = VsdCredentials(
    vsd_server=VSD_CONF.nuage_vsd_server,
    user=VSD_CONF.nuage_vsd_user,
    password=VSD_CONF.nuage_vsd_password,
    base_uri=VSD_CONF.nuage_base_uri,
    enterprise=VSD_CONF.nuage_default_netpartition)
CMS_ID = VSD_CONF.nuage_cms_id


class VSDTestHelper(VsdClient):

    def __init__(self, cms_id=None):
        super(VSDTestHelper, self).__init__(
            cms_id if cms_id else CMS_ID)

    def authenticate(self, credentials=None):
        super(VSDTestHelper, self).authenticate(
            credentials if credentials else VSD_CREDENTIALS)

    def create_gateway(self, **kwargs):
        new_gateway = self.vspk_helper.vspk.NUGateway(**kwargs)
        return self.vspk_helper.get_user().create_child(new_gateway)[0]

    def create_gateway_port(self, gateway, **kwargs):
        new_port = self.vspk_helper.vspk.NUPort(**kwargs)
        return gateway.create_child(new_port)[0]

    def create_egress_acl_entry(self, **kwargs):
        return self.vspk_helper.vspk.NUEgressACLEntryTemplate(**kwargs)
