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

import argparse
import sys


class Main(object):

    cmd = 'nuage-openstack-auditor'
    resources = '''
Supported resources are:
   fwaas       FWaaS resources
   all         All above mentioned resources
'''
    usage = cmd + ''' [-v|-d] <resources> [--report <report-file>]

''' + resources

    def __init__(self):
        parser = argparse.ArgumentParser(prog=self.cmd, usage=self.usage)
        parser.add_argument('-v', '--verbose', help='verbose output',
                            action="store_true")
        parser.add_argument('-d', '--debug', help='log with debug level',
                            action="store_true")
        parser.add_argument('resources', help='Resources to audit')
        parse_index = 1
        self.debug = self.verbose = False
        while parse_index < len(sys.argv):
            if sys.argv[parse_index] in ['-d', '--debug']:
                self.debug = True
                parse_index += 1
            elif sys.argv[parse_index] in ['-v', '--verbose']:
                self.verbose = True
                parse_index += 1
            else:
                break
        if len(sys.argv) == parse_index:
            parser.print_help()
            exit(1)
        args = parser.parse_args(
            sys.argv[parse_index:parse_index + 1])
        if not hasattr(self, args.resources):
            parser.print_help()
            exit(1)
        getattr(self, args.resources)(parse_index)

    def fwaas(self, parse_index):
        self.audit('fwaas', parse_index)

    def all(self, parse_index):
        self.audit('all', parse_index)

    def audit(self, resources, parse_index):
        report_file = None
        if len(sys.argv) > parse_index + 1:
            if sys.argv[parse_index + 1] == '--report':
                if len(sys.argv) > parse_index + 2:
                    report_file = sys.argv[parse_index + 2]
                else:
                    print("ERROR: --report given: please specify report file.")
                    exit(1)

        from nuage_openstack_audit.audit import Audit
        Audit(report_file, self.verbose, self.debug).do_audit(resources)


def main():
    Main()
