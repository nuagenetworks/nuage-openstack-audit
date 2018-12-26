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

import os
import traceback


class Utils(object):

    @staticmethod
    def env_error(msg, *args):
        raise EnvironmentError((msg % tuple(args)) if args else msg)

    @staticmethod
    def report_traceback(reporter):
        reporter.report(traceback.format_exc())

    @staticmethod
    def get_env_var(name, default=None, required=False):
        assert default is None or not required  # don't set default and
        #                                         required at same time
        try:
            if os.environ[name] is not None:
                return os.environ[name]
            else:
                return default
        except KeyError:
            if not required:
                return default
            else:
                Utils.env_error('Please set %s. Aborting.', name)

    @staticmethod
    def get_env_bool(name, default=False):
        return (str(Utils.get_env_var(name, default)).lower()
                in ['t', 'true', 'yes', 'y', '1'])
