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

from abc import ABCMeta

import json
import six

from nuage_openstack_audit.vsdclient.common.cms_id_helper import strip_cms_id
from nuage_openstack_audit.vsdclient.common import constants

REST_SUCCESS_CODES = constants.REST_SUCCESS_CODES
REST_NOT_FOUND = constants.RES_NOT_FOUND
DEF_OPENSTACK_USER = constants.DEF_OPENSTACK_USER
DEF_OPENSTACK_USER_EMAIL = constants.DEF_OPENSTACK_USER_EMAIL
REST_SERV_UNAVAILABLE_CODE = constants.REST_SERV_UNAVAILABLE_CODE


class NuageServerBaseClass(object):
    def __init__(self, create_params=None, extra_params=None):
        self.create_params = create_params
        self.extra_params = extra_params
        self.error_msg = None
        self.vsd_error_code = None

    def validate(self, response):
        if response[0] == 0:
            return False
        if response[0] not in REST_SUCCESS_CODES:
            errors = json.loads(response[3])
            if response[0] == REST_SERV_UNAVAILABLE_CODE:
                self.error_msg = self.get_503_error_msg(errors)
            else:
                self.error_msg = self.get_error_msg(errors)
                if response[0] == REST_NOT_FOUND:
                    # 404s don't have an internalErrorCode
                    self.vsd_error_code = REST_NOT_FOUND
                else:
                    self.vsd_error_code = self.get_internal_error_code(errors)
            return False
        return True

    def get_503_error_msg(self, errors):
        return 'VSD temporarily unavailable, ' + str(errors['errors'])

    def get_error_msg(self, errors):
        return str(errors['errors'][0]['descriptions'][0]['description'])

    def get_internal_error_code(self, errors):
        return str(errors.get('internalErrorCode'))

    def get_response_objid(self, response):
        return str(response[3][0]['ID'])

    def get_response_objtype(self, response):
        if 'type' in response[3][0]:
            return str(response[3][0]['type'])

    def get_response_obj(self, response):
        return response[3][0]

    def get_response_objlist(self, response):
        return response[3]

    def get_response_parentid(self, response):
        return response[3][0]['parentID']

    def get_response_externalid(self, response):
        return strip_cms_id(response[3][0]['externalID'])

    def get_description(self, response):
        return response[3][0]['description']

    def get_validate(self, response):
        return self.validate(response) and response[3]

    def check_response_exist(self, response):
        return len(response[3]) > 0

    def delete_validate(self, response):
        return (self.validate(response) or
                response[0] == constants.RES_NOT_FOUND)

    def get_error_code(self, response):
        return response[0]

    def resource_exists(self, response):
        error_code = self.get_error_code(response)
        if error_code == 0:
            return False
        errors = json.loads(response[3])
        int_error_code = self.get_internal_error_code(errors)
        # 2510 is the internal error code returned by VSD in case
        # template already exists
        if (error_code != constants.CONFLICT_ERR_CODE or
            (error_code == constants.CONFLICT_ERR_CODE and
             int_error_code != constants.RES_EXISTS_INTERNAL_ERR_CODE)):
            return False
        return True

    def extra_header_filter(self, **filters):
        filter = ''
        for field, value in filters.iteritems():
            if isinstance(value, six.string_types):
                value = "'%s'" % value
            if value is None:
                value = 'null'
            if filter:
                filter += " and "
            filter += "%s IS %s" % (field, value)
        return {'X-Nuage-Filter': filter} if filter else None

    def single_filter_header(self, **filters):
        filter = ''
        field = filters.keys()[0]
        for value in filters[field]:
            if isinstance(value, six.string_types):
                value = "'%s'" % value
            if value is None:
                value = 'null'
            if filter:
                filter += " or "
            filter += "%s IS %s" % (field, value)
        return {'X-Nuage-Filter': filter} if filter else None


class NuageCms(NuageServerBaseClass):
    def post_resource(self):
        return '/cms'

    def post_data(self):
        return {"name": self.create_params['name']}

    def get_resource(self):
        return '/cms/%s' % self.create_params['cms_id']


class NuageNetPartition(NuageServerBaseClass):
    def post_resource(self):
        return '/enterprises'

    def get_resource(self):
        return '/enterprises'

    def get_resource_by_id(self):
        return '/enterprises/%s' % self.create_params['netpart_id']

    def default_post_data(self):
        data = {
            'allowedForwardingClasses': ['E', 'F', 'G', 'H']
        }
        return data

    def post_data(self):
        data = {
            'name': self.create_params['name'],
            'floatingIPsQuota': self.create_params['fp_quota'],
        }
        data.update(self.default_post_data())
        return data

    def get_net_partition_id(self, response):
        return self.get_response_objid(response)

    def get_validate(self, response):
        return self.validate(response) and response[3]

    def delete_resource(self, id):
        return '/enterprises/%s?responseChoice=1' % id

    def extra_headers_get(self):
        headers = {}
        headers['X-NUAGE-FilterType'] = "predicate"
        headers['X-Nuage-Filter'] = "name IS '%s'" % self.create_params['name']
        return headers


@six.add_metaclass(ABCMeta)
class VsdResource(object):
    resource = None

    @classmethod
    def get_url(cls):
        return '/%s' % cls.resource

    @classmethod
    def show_url(cls):
        return '/%s/%%s' % cls.resource

    @classmethod
    def post_url(cls):
        return cls.get_url() + '?responseChoice=1'

    @classmethod
    def put_url(cls):
        return cls.show_url() + '?responseChoice=1'

    @classmethod
    def delete_url(cls):
        return cls.show_url() + '?responseChoice=1'

    @staticmethod
    def extra_header_filter(**filters):
        filter = ''
        for field, value in filters.iteritems():
            if isinstance(value, six.string_types):
                value = "'%s'" % value
            if value is None:
                value = 'null'
            if filter:
                filter += " and "
            filter += "%s IS %s" % (field, value)
        return {'X-Nuage-FilterType': 'predicate',
                'X-Nuage-Filter': filter} if filter else None


@six.add_metaclass(ABCMeta)
class VsdChildResource(VsdResource):
    @classmethod
    def get_url(cls, parent=None, parent_id=None):
        if parent and parent_id:
            return '/%s/%s/%s' % (parent, parent_id, cls.resource)
        else:
            return super(VsdChildResource, cls).get_url()

    @classmethod
    def post_url(cls, parent=None, parent_id=None):
        return cls.get_url(parent=parent,
                           parent_id=parent_id) + '?responseChoice=1'


class Domain(VsdChildResource):
    resource = 'domains'


class FirewallRule(VsdChildResource):
    resource = 'firewallrules'


class FirewallAcl(VsdChildResource):
    resource = 'firewallacls'

    @classmethod
    def insert_url(cls):
        return cls.show_url() + '/insert?responseChoice=1'

    @classmethod
    def remove_url(cls):
        return cls.show_url() + '/remove?responseChoice=1'

    @classmethod
    def domains_url(cls):
        return cls.show_url() + '/domains?responseChoice=1'
