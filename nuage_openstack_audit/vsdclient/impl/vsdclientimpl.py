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

import logging

from nuage_openstack_audit.utils.timeit import TimeIt

from nuage_openstack_audit.vsdclient.common import cms_id_helper
from nuage_openstack_audit.vsdclient.common import nuagelib
from nuage_openstack_audit.vsdclient.resources import fwaas
from nuage_openstack_audit.vsdclient.resources import netpartition
from nuage_openstack_audit.vsdclient import restproxy
from nuage_openstack_audit.vsdclient.vsdclient import VsdClient

LOG = logging.getLogger(__name__)


class VsdClientImpl(VsdClient):

    def __init__(self, cms_id, **kwargs):
        super(VsdClientImpl, self).__init__()
        self.restproxy = restproxy.SingleThreadedRESTProxyServer(**kwargs)
        self.restproxy.generate_nuage_auth()

        self.verify_cms(cms_id)
        cms_id_helper.CMS_ID = cms_id

        self.net_part = netpartition.NuageNetPartition(self.restproxy)
        self.fwaas = fwaas.NuageFwaas(self.restproxy)

    def get_netpartition_by_name(self, name):
        return self.net_part.get_netpartition_by_name(name)

    def verify_cms(self, cms_id):
        cms = nuagelib.NuageCms(create_params={'cms_id': cms_id})
        response = self.restproxy.rest_call('GET', cms.get_resource(), '')
        if not cms.get_validate(response):
            LOG.error('CMS with id %s not found on vsd', cms_id)
            raise restproxy.RESTProxyError(cms.error_msg)

    @TimeIt.timeit
    def get_firewalls(self, enterprise_id):
        return self.fwaas.get_firewalls(enterprise_id)

    @TimeIt.timeit
    def get_firewall_policies(self, enterprise_id):
        return self.fwaas.get_firewall_acls(enterprise_id)

    @TimeIt.timeit
    def get_firewall_rules(self, enterprise_id):
        return self.fwaas.get_firewall_rules(enterprise_id)

    def get_firewall_rules_by_policy(self, enterprise_id, os_policy_id):
        return self.fwaas.get_firewall_rules_by_os_policy(enterprise_id,
                                                          os_policy_id)

    def get_firewall_rules_by_ids(self, enterprise_id, os_rule_ids):
        return self.fwaas.get_firewall_rules_by_ids(enterprise_id,
                                                    os_rule_ids)
