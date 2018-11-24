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

from nuage_openstack_audit.vsdclient.vsdclient import VsdClient


class VSDTestHelper(VsdClient):

    def __init__(self, cms_id):
        super(VSDTestHelper, self).__init__(cms_id)

    def create_gateway(self, **kwargs):
        new_gateway = self.vspk_helper.vspk.NUGateway(**kwargs)
        return self.vspk_helper.get_user().create_child(new_gateway)[0]

    def create_gateway_port(self, gateway, **kwargs):
        new_port = self.vspk_helper.vspk.NUPort(**kwargs)
        return gateway.create_child(new_port)[0]
