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

import itertools


def _chunks(l, n):
    """Split a list l in chunks of length n."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def _chunked_extra_header_match_any_filter(field, values,
                                           max_predicates_per_request=80):
    """Create X-Nuage-Filters to fetch objects that have 'field' in 'values'.

    Selective fetching of objects from the VSD is possible using the
    X-Nuage-Filter header. This header is sent in a GET request for which
    the max header size is limited (currently 8K). In order to not exceed
    this value, it was decided to, for now, default it to the magic number 50,
    this works well for the (only) use case where we fetch FirewallRules
    by externalID, leaving still some room in the header protecting us
    against unexpected changes in the header size by future developments

    :param field: name of the field in VSD used for filtering
    :param values: list of values for that field
    :param max_predicates_per_request: max number of predicates per GET request
    :return: chunked headers
    """
    is_in_supported = False

    if not values:
        yield None
    elif is_in_supported:
        for chunk in _chunks(values, max_predicates_per_request):
            yield {'X-Nuage-FilterType': 'predicate',
                   'X-Nuage-Filter': '{} IN {{"{}"}}'.format(
                       field, '","'.join(chunk))}
    else:
        for chunk in _chunks(values, max_predicates_per_request):
            yield {'X-Nuage-FilterType': 'predicate',
                   'X-Nuage-Filter':
                       " OR ".join("{} IS '{}'".format(field, value)
                                   for value in chunk)}


def get_by_field_values(restproxy_serv, vsd_resource, field_name, field_values,
                        **kwargs):
    """Get objects which have field_name IN(field_values).

    :param restproxy_serv: RESTProxy
    :param vsd_resource: The resource to get
    :param field_name: The name of the field used for filtering
    :param field_values: The values used for filtering
    :param kwargs: arguments for vsd_resource.get_url
    :return:
    """
    chunked_headers = _chunked_extra_header_match_any_filter(field_name,
                                                             field_values)
    url = vsd_resource.get_url(**kwargs)
    iterators = (restproxy_serv.get(url, extra_headers=header, required=True)
                 for header in chunked_headers if header)
    return itertools.chain.from_iterable(iterators)
