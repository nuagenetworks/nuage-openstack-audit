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

from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.utils import Utils

USER = Reporter('USER')

DEVELOPER_MODUS = Utils.get_env_bool('OS_AUDIT_DEVELOPER_MODUS')
VERBOSE = Utils.get_env_bool('OS_AUDIT_VERBOSE')
EXTREME_VERBOSE = Utils.get_env_bool('OS_AUDIT_EXTREME_VERBOSE')
LOG_LEVEL = Utils.get_env_var('OS_AUDIT_LOG_LEVEL', 'INFO')
DEBUG = 'debug' in LOG_LEVEL.lower()


class MainArgs(object):
    def __init__(self, resource, report=None, project=None,
                 verbose=None, extreme_verbose=False, developer_modus=None):
        assert resource in ['fwaas', 'security_group', 'all']

        self.resource = resource
        self.report = report
        self.project = project
        self.no_log = True  # no log files as part of testing

        # set flags
        self.debug = DEBUG
        self.verbose = verbose if verbose is not None else VERBOSE
        self.extreme_verbose = (
            extreme_verbose if extreme_verbose is not None
            else EXTREME_VERBOSE)
        self.developer_modus = (
            developer_modus if developer_modus is not None
            else DEVELOPER_MODUS)
        if self.developer_modus:
            self.verbose = True
            self.extreme_verbose = True
            self.debug = True

        # log
        if self.developer_modus:
            USER.blue('Developer modus is on, '
                      'which implies debug & extreme verbose')
        else:

            if not self.extreme_verbose:
                USER.blue('VERBOSE is %s, set OS_AUDIT_VERBOSE to change',
                          self.verbose)
            if self.verbose or self.extreme_verbose:
                USER.blue('Extreme VERBOSE is %s, '
                          'set OS_AUDIT_EXTREME_VERBOSE to change',
                          self.extreme_verbose)
            USER.blue('DEBUG is %s, set OS_AUDIT_LOG_LEVEL to change',
                      self.debug)

        USER.newline()
