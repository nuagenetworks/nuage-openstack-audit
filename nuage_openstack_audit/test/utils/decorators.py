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

import functools
import six
import time

REPORT_EXECUTION_TIME = False


def header():
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            if six.get_function_code(f).co_name != 'wrapper':
                print("\n=== START of {} ===".format(
                    six.get_function_code(f).co_name))
            start_time = time.time()
            result = f(self, *func_args, **func_kwargs)
            if six.get_function_code(f).co_name != 'wrapper':
                if REPORT_EXECUTION_TIME:
                    exec_time = int(time.time() - start_time)
                    print("=== Execution time = {} SECS ===".format(exec_time))
                print("=== END of {} ===".format(
                    six.get_function_code(f).co_name))
            return result
        return wrapper
    return decorator
