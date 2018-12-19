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

from collections import Counter
import six
import testtools

from nuage_openstack_audit.utils.logger import Reporter

WARN = Reporter('WARN')


class TestBase(testtools.TestCase):

    @staticmethod
    def check_in(needle, haystack, message='Expected {} be in {}'):
        if needle not in haystack:
            Reporter('WARN').report(message.format(needle, haystack))
            return False
        else:
            return True

    def assert_in(self, needle, haystack, message='Expected {} be in {}'):
        if not self.check_in(needle, haystack, message):
            self.assertIn(needle, haystack, message)

    @staticmethod
    def check_equal(expected, observed,
                    message='Expected {}, got {}'):
        if expected != observed:
            Reporter('WARN').report(message.format(expected, observed))
            return False
        else:
            return True

    def assert_equal(self, expected, observed,
                     message='Expected {}, got {}'):
        if not self.check_equal(expected, observed, message):
            self.assertEqual(expected, observed, message)

    def assert_audit_report_length(self, expected_length, audit_report):
        actual_length = len(audit_report)
        if not self.check_equal(expected_length,
                                actual_length,
                                'Expected {} discrepancies, got {}'):
            WARN.pprint(audit_report)
            self.assert_equal(expected_length, actual_length)

    def assert_entities_in_sync(self, expected, observed):
        self.assert_equal(expected,
                          sum(six.itervalues(observed)) if isinstance(
                              observed, Counter) else observed,
                          'Expected {} entities in sync, got {}')

    def assert_counter_equal(self, expected, observed):
        # remove zero's
        expected += Counter()
        observed += Counter()

        self.assert_equal(expected, observed)
