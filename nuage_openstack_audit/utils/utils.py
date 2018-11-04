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

import os
import sys

from nuage_openstack_audit.utils.logger import Reporter


class Utils(object):
    class TestMainArgs(object):
        def __init__(self, resource, report=None,
                     verbose=False, extreme_verbose=False, debug=False):
            self.resource = resource
            self.report = report
            self.verbose = verbose
            self.extreme_verbose = extreme_verbose
            self.debug = debug

    @staticmethod
    def env_error(*args):
        Reporter('ERROR').report(*args)
        raise EnvironmentError

    @staticmethod
    def get_env_var(name, default=None):
        try:
            if os.environ[name] or default is None:
                return os.environ[name]
            else:
                return default
        except KeyError:
            if default is not None:
                return default
            else:
                Utils.env_error('ERROR: Please set %s. Aborting.', name)

    @staticmethod
    def get_env_bool(name, default=False):
        return str(Utils.get_env_var(name, default)).lower() == 'true'

    @staticmethod
    def boolean_question(question):
        print(question + ' [y|N] ', end='')
        answer = sys.stdin.readline().strip().lower()
        return answer and answer == 'y'
