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

from nuage_openstack_audit.vsdclient.common import nuagelib


class NuageNetPartition(object):
    def __init__(self, restproxy):
        self.restproxy = restproxy

    def get_netpartition_by_name(self, name):
        req_params = {
            'name': name
        }
        netpartition = nuagelib.NuageNetPartition(create_params=req_params)
        nuage_ent_extra_headers = netpartition.extra_headers_get()
        response = self.restproxy.rest_call(
            'GET', netpartition.get_resource(),
            '', extra_headers=nuage_ent_extra_headers)
        if netpartition.get_validate(response):
            netpartition = netpartition.get_response_obj(response)
            return {
                'id': netpartition['ID'],
                'name': netpartition['name'],
                'description': netpartition['description'],
                'neutron_id': netpartition['externalID'],
            }
