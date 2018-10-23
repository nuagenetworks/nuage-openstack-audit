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

from __future__ import print_function

import contextlib
import functools
import logging
import six
import sys

from nuage_openstack_audit.vsdclient.common import exceptions as nuage_exc
from nuage_openstack_audit.vsdclient.restproxy import RESTProxyError


def get_logger(name=None, fn=None):
    return logging.getLogger(fn.__module__ if fn else name)


def handle_nuage_api_error(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as ex:
            _, _, tb = sys.exc_info()
            six.reraise(nuage_exc.NuageAPIException,
                        nuage_exc.NuageAPIException(msg=ex.message),
                        tb)
    return wrapped


def context_log(fn):
    def wrapped(*args, **kwargs):
        instance = args[0]
        class_name = instance.__class__.__name__
        method_name = fn.__name__
        context = args[1]
        LOG = get_logger(fn=fn)
        LOG.debug('%s method %s is getting called with context.current %s, '
                  'context.original %s',
                  class_name, method_name, context.current, context.original)
        return fn(*args, **kwargs)
    return wrapped


class Ignored(object):
    """Class that will evaluate to False in if-statement and contains error.

    This is returned when exceptions are silently ignored from vsdclient.
    It will return false when doing if x:
    But it's still possible to raise the original exception by doing
    raise x.exception
    """

    def __init__(self, exception):
        self.exception = exception

    def __nonzero__(self):
        return False


def retry_on_vsdclient_error(fn, nr_retries=3, vsd_error_codes=None):
    """Retry function on vsdclient error.

    :param fn: function to (re)try
    :param nr_retries
    :param vsd_error_codes: vsd_error_codes to retry [(http_code, vsd_code)]
        [(409,'7010')]
    """
    def wrapped(*args, **kwargs):
        tries = 1
        while tries <= nr_retries:
            try:
                return fn(*args, **kwargs)
            except RESTProxyError as e:
                LOG = get_logger(fn=fn)
                if tries == nr_retries:
                    LOG.debug('Failed to execute {} {} times.'.format(
                        fn.func_name, nr_retries)
                    )
                    raise
                if (e.code, e.vsd_code) in vsd_error_codes:
                    LOG.debug('Attempt {} of {} to execute {} failed.'.format(
                        tries, nr_retries, fn.func_name)
                    )
                    tries += 1
                else:
                    LOG.debug('Non retry-able error '
                              'encountered on {}.'.format(fn.func_name))
                    raise
    return wrapped


def handle_nuage_api_errorcode(fn):
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            _, _, tb = sys.exc_info()
            six.reraise(nuage_exc.NuageBadRequest,
                        nuage_exc.NuageBadRequest(
                            msg=ERROR_DICT.get(str(e.vsd_code), e.message)),
                        tb)

    return wrapped


def ignore_no_update(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            # See ERROR_DICT below. This should never go to the user. Neutron
            # does not complain when updating to the same values.
            if str(e.vsd_code) == '2039':
                return Ignored(e)
            raise
    return wrapped


def ignore_not_found(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RESTProxyError as e:
            # We probably want to ignore 404 errors when we're deleting anyway.
            if str(e.vsd_code) == '404':
                return Ignored(e)
            raise
    return wrapped


ERROR_DICT = {
    '2039': "There are no attribute changes to modify the entity.",
    '2050': "Netpartition does not match the network.",
    '7022': "Redirection target belongs to a different subnet.",
    '7027': ("Redirection target already has a port assigned. Can't assign"
             " more with redundancy disabled."),
    '7036': "The port is in an L2Domain, it can't have floating ips",
    '7038': "Nuage floatingip is not available for this port",
    '7309': "Nuage policy group is not available for this port"
}


def filters_to_vsd_filters(filterables, filters, os_to_vsd):
    """Translate openstack filters to vsd filters.

    :param filterables: The attributes which are filterable on VSD.
    :param filters: the neutron filters list from a list request.
    :param os_to_vsd: a dict where the key is the neutron name, and the key is
     the vsd attribute name. For example {'rd': 'routeDistinguisher', ...}
     the key can also be a method which will be called with this method's
     return dict and the 'filters' parameter.
    :return: A dict with vsd-friendly keys and values taken from the filters
     parameter
    """
    if not filters or not filterables or not os_to_vsd:
        return {}
    vsd_filters = {}
    for filter in filterables:
        if filter in filters:
            vsd_key = os_to_vsd[filter]
            if hasattr(vsd_key, '__call__'):
                vsd_key(vsd_filters, filters)
            else:
                vsd_filters[vsd_key] = filters[filter][0]
    return vsd_filters


def add_rollback(rollbacks, method, *args, **kwargs):
    rollbacks.append(functools.partial(method, *args, **kwargs))


@contextlib.contextmanager
def rollback():
    rollbacks = []
    log = get_logger()
    try:
        yield functools.partial(add_rollback, rollbacks)
    except Exception:
        for action in reversed(rollbacks):
            try:
                action()
            except Exception:
                log.exception("Rollback failed.")
        raise
