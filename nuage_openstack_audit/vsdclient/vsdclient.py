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


class VsdClient(FWaaSMixin, SecurityGroupsMixin):

    def __init__(self, vsd_server, user, password, enterprise, base_uri,
                 cms_id):

        # Connect to vsp with vspk
        version = 'v{}'.format(search(r'(\d+_\d+)', base_uri).group())
        self.vspk_helper = VspkHelper(vsd_server, user, password, enterprise,
                                      version, cms_id)

        # Init all base classes here
        FWaaSMixin.__init__(self, self.vspk_helper)
        SecurityGroupsMixin.__init__(self, self.vspk_helper)
