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

from __future__ import division

import functools
import importlib
from itertools import chain
import logging
from math import ceil

from bambou import NURESTObject
from bambou import NURESTSession

LOG = logging.getLogger(__name__)


class RecreateSessionOnTimeout(object):
    """Decorator class to automatically re-authenticate when session expires.

    Warning: Not thread-safe (yet)
    """

    def __init__(self, method):
        self.method = method
        self.renewing = False

    def __get__(self, obj=None, objtype=None):
        @functools.wraps(self.method)
        def _wrapper(*args, **kwargs):
            connection = self.method(obj, *args, **kwargs)

            if connection.response.status_code == 401 and not self.renewing:
                LOG.debug("Renewing vspk session")
                self.renewing = True
                session = NURESTSession.get_current_session()
                session.reset()
                session.start()
                self.renewing = False
                return self.method(obj, *args, **kwargs)
            else:
                return connection
        return _wrapper


# Monkey patch Bambou
NURESTObject.send_request = RecreateSessionOnTimeout(NURESTObject.send_request)


class VspkHelper(object):
    """Helper class for interfacing with vspk."""

    def __init__(self, cms_id):
        self.cms_id = cms_id
        self.session = None
        self.default_enterprise = None
        self.vspk = None

    def authenticate(self, vsd_credentials):
        # Connect to VSP
        LOG.debug('Setting up vspk')
        self.vspk = importlib.import_module('vspk.{}'.format(
            vsd_credentials.api_version))
        self.session = self.vspk.NUVSDSession(
            username=vsd_credentials.user,
            password=vsd_credentials.password,
            enterprise='csp',
            api_url='https://{}'.format(vsd_credentials.vsd_server))
        try:
            self.session.start()
        except Exception as e:
            LOG.debug('Failed connecting with VSD: %s', e)
            raise EnvironmentError('Could not connect with VSD.')
        else:
            LOG.debug('Started vspk session')

        # Store default enterprise
        self.default_enterprise = self.session.user.enterprises.get(
            filter='name is "{}"'.format(vsd_credentials.enterprise))[0]
        if not self.default_enterprise:
            raise EnvironmentError('Default enterprise %s '
                                   'not found' % vsd_credentials.enterprise)
        return self

    def get_default_enterprise(self):
        return self.default_enterprise

    def get_user(self):
        return self.session.user

    def get_external_id(self, os_id):
        return '{}@{}'.format(os_id, self.cms_id)

    def get_external_id_filter(self, object_id):
        return 'externalID IS "{}"'.format(
            self.get_external_id(object_id))

    @staticmethod
    def get_vsd_filter(keys, values):
        filter_str = ""
        if not (isinstance(keys, list) and isinstance(values, list)):
            keys = [keys]
            values = [values]
        for key, value in zip(keys, values):
            if filter_str:
                filter_str += " and "
            filter_str += "{} IS '{}'".format(key, value)
        return filter_str

    @staticmethod
    def get_all(parent, fetcher_str, **kwargs):
        """Get all objects, abstracting away vsd paging.

        :param parent: parent vspk object
        :param fetcher_str: name of attribute to fetch from parent
        :param kwargs: extra arguments for fetcher.get
        :return: a generator for the objects

        TODO this should be moved to vspk
        """
        # overwrite parameters that may interfere
        kwargs.update({'commit': True, 'page': 0})

        def generate_all_pages():
            """generator for all pages."""
            fetcher = getattr(parent, fetcher_str)

            first_page = fetcher.get(**kwargs)
            kwargs['page_size'] = len(first_page)
            count = fetcher.current_total_count
            yield first_page

            if count > kwargs['page_size']:
                num_pages = int(ceil(count / kwargs['page_size']))
                for page in range(1, num_pages):
                    kwargs['page'] = page
                    yield fetcher.get(**kwargs)

        # flatten the pages into one generator for just the objects
        return chain.from_iterable(generate_all_pages())

    @classmethod
    def get_all_by_field(cls, parent, fetcher_str, field_name,
                         field_values, **kwargs):
        """Get all objects which have field_name in field_values.

        :param parent: parent vspk object
        :param fetcher_str: name of attribute to fetch from parent
        :param field_name: field for which we want to filter
        :param field_values: filter values
        :param kwargs: extra arguments for fetcher.get
        :return: chain from iterable of retrieved objects
        """
        if 'filter' in kwargs:
            raise NotImplementedError("Additional filter not supported")

        # Selective fetching of objects from the VSD is possible using the
        # X-Nuage-Filter header. This header is sent in a GET request for which
        # the max header size is limited (currently 8K). In order to not exceed
        # this value, it was decided to, for now, default it to 50.
        filters = cls._chunked_match_any_filter(field_name, field_values,
                                                max_values_per_chunk=50)

        objects = (cls.get_all(parent, fetcher_str, filter=f, **kwargs)
                   for f in filters if f)
        return chain.from_iterable(objects)

    @classmethod
    def _chunked_match_any_filter(cls, field, values, max_values_per_chunk):
        # TODO(Glenn) X-Nuage-Filter supports 'IN {..}' for newer vsd versions
        if not values:
            yield None
        else:
            for chunk in cls._chunkify(values, max_values_per_chunk):
                yield " OR ".join("{} IS '{}'".format(field, value)
                                  for value in chunk)

    @staticmethod
    def _chunkify(sequence, chunksize):
        """Yield successive chunks from `sequence`."""
        for i in range(0, len(sequence), chunksize):
            yield sequence[i:i + chunksize]
