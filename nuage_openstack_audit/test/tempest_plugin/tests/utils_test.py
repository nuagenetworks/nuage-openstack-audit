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

from nuage_openstack_audit.test.tempest_plugin.tests.utils.decorators \
    import header
from nuage_openstack_audit.utils.logger import get_logger
from nuage_openstack_audit.utils.logger import Reporter

# run me using:
# python -m testtools.run nuage_openstack_audit/test/utils_test.py

USER = Reporter('USER')
WARN = Reporter('WARN')


class UtilsTest(testtools.TestCase):

    @classmethod
    def setUpClass(cls):
        super(UtilsTest, cls).setUpClass()
        USER.report('\n===== Start of tests (%s) =====', cls.__name__)

        logger = get_logger()
        logger.set_verbose(True)
        logger.set_extreme_verbose(True)
        logger.init_logging('DEBUG')

        WARN.h0('VERBOSE is forcibly set to TRUE')
        WARN.h0('Extreme VERBOSE is forcibly set to TRUE')
        WARN.h0('DEBUG is forcibly set to TRUE')

    @classmethod
    def tearDownClass(cls):
        super(UtilsTest, cls).tearDownClass()
        USER.report('\n===== End of tests (%s) =====', cls.__name__)

        Reporter().newline()

    @header()
    def test_reporting(self):
        Reporter('INFO').h1('Avocados are ', end='').green('green')
        Reporter('INFO').h1('Bananas are ', end='').yellow('yellow')
        Reporter('DEBUG').h1('Grapes are blue')
