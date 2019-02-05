# Copyright 2015
# All Rights Reserved.
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

from oslo_config import cfg

nuage_vsd_group = cfg.OptGroup(name='nuage_openstack_audit',
                               title='Nuage VSD config options')

NuageVsdGroup = [
    cfg.StrOpt('nuage_vsd_server',
               default="localhost:8443",
               help="Nuage vsd server"),
    cfg.StrOpt('nuage_default_netpartition',
               default="OpenStackDefaultNetPartition",
               help="default nuage netpartition name"),
    cfg.StrOpt('nuage_auth_resource',
               default="/me",
               help="api path to authenticate for nuage vsd"),
    cfg.StrOpt('nuage_base_uri',
               default="/nuage/api/v5_0",
               help="base nuage vsd api url"),
    cfg.StrOpt('nuage_vsd_user',
               default='csproot',
               help="nuage vsd user"),
    cfg.StrOpt('nuage_vsd_password',
               default='csproot',
               help='nuage vsd user password'),
    cfg.StrOpt('nuage_vsd_org',
               default='csp',
               help='nuage vsd organization name'),
    cfg.StrOpt('nuage_cms_id', default=None,
               help=('ID of a Cloud Management System on the VSD which '
                     'identifies this OpenStack instance')),
    cfg.StrOpt('mysql_password', default='root',
               help='MySQL root password')
]
