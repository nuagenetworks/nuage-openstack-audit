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

from abc import abstractmethod
from functools import partial
from functools import reduce


def calculate_discrepancies(observed_vsd_obj, expected_vsd_obj):
    # Loop over the vsd object in a deterministic order so discrepancies
    # are also reported consistently (improves testability)
    discrepancies = []
    for attr_name in sorted(expected_vsd_obj.keys()):
        mapped_value = expected_vsd_obj[attr_name]
        original_value = getattr(observed_vsd_obj, attr_name)
        if str(mapped_value) != str(original_value):
            discrepancies.append(
                (attr_name, '{} != {}'.format(mapped_value, original_value)))
    return discrepancies


class Matcher(object):

    @abstractmethod
    def entity_name(self):
        pass

    def get_mapper(self):
        return {}

    @abstractmethod
    def map_to_vsd_objects(self, neutron_obj):
        """Map neutron object to list of expected valid VSD representations"""
        return []

    def map_neutron_to_vsd(self, neutron_obj):

        # map to a list of equivalent vsd representations
        mapping = self.map_to_vsd_objects(neutron_obj)
        if mapping:
            return mapping

        # mapping by a mapper
        else:
            mapping = self.get_mapper()
            result = {}
            for key in neutron_obj:
                if key in mapping and key in neutron_obj:
                    for attr_mapping in mapping[key]:
                        result_key, method = attr_mapping
                        result[result_key] = method(neutron_obj[key])
            return [result]

    def compare(self, neutron_obj, vsd_obj):
        # Translate the observed neutron object to one or more
        # valid VSD representations that we can expect on VSD.
        # More than one valid representation on VSD can exist e.g
        # after a nuage-openstack-neutron plugin refactoring which did not
        # include an upgrade script but changed the way how objects are
        # created in VSD
        expected_vsd_objects = self.map_neutron_to_vsd(neutron_obj)

        # Calculate the lists of discrepancies between the observed vsd object
        # and each of the valid candidate VSD object that we expect
        discrepancies = map(partial(calculate_discrepancies, vsd_obj),
                            expected_vsd_objects)

        # Return the shortest discrepancy list
        # i.e. the list of discrepancies for which an expected VSD object
        # matches best with the observed VSD object
        return reduce(lambda a, b: a if len(a) < len(b) else b, discrepancies)
