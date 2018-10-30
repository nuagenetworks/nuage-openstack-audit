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

import testtools

from nuage_openstack_audit.main import Main
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.utils import Utils

# run me using:
# python -m testtools.run nuage_openstack_audit/test/utils_test.py

WARN = Reporter('WARN')


class UtilsTest(testtools.TestCase):

    @classmethod
    def setUpClass(cls):

        WARN.h0('VERBOSE is forcibly set to TRUE')
        WARN.h0('Extreme VERBOSE is forcibly set to TRUE')
        WARN.h0('DEBUG is forcibly set to TRUE')

        cls.main = Main(Utils.TestMainArgs('all', None, True, True, True))

    @classmethod
    def tearDownClass(cls):
        Reporter().newline()

    def test_info(self):
        Reporter('INFO').h1('[INFO] Bananas are ', end='').set_color(
            Reporter.YELLOW).report('yellow', end='').endc().report(
            ' and avocados are ', end='').set_color(
            Reporter.GREEN).report('green', end='').endc()

    def test_debug(self):
        Reporter('DEBUG').h1('[DEBUG] Grapes are blue')
