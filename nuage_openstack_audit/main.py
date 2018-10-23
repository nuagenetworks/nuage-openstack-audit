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
import json
import os
import time

from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.utils import Utils

USER = Reporter('USER')
INFO = Reporter('INFO')


class Main(object):

    program = 'nuage-openstack-audit'

    description = '''
    Nuage OpenStack Audit is auditing networking resources between
    OpenStack neutron and the Nuage Networks VCS platform.'''

    def __init__(self, args=None):

        self.initiating_time = time.strftime("%d-%m-%Y_%H:%M:%S")

        if not args:
            parser = argparse.ArgumentParser(prog=self.program,
                                             description=self.description)
            parser.add_argument('-v', '--verbose', help='verbose output',
                                action="store_true")
            parser.add_argument('-d', '--debug', help='log with debug level',
                                action="store_true")
            parser.add_argument('-o', '--report', help='report file',
                                default=None)
            parser.add_argument('resource', help='resource to audit',
                                choices=['fwaas', 'all'])
            args = parser.parse_args()

        self.debug = args.debug
        self.verbose = args.verbose
        self.report = args.report
        self.resource = args.resource

        self.init_logger(self.initiating_time)

    def run(self):
        start_time = time.time()
        report_file = (self.report if self.report
                       else self.prep_report_name(self.initiating_time))

        USER.h1('Authenticating with OpenStack')
        neutron = self.create_os_client().neutron()

        USER.h1('Authenticating with Nuage VSD')
        vsd = self.create_vsd_client()

        # -- all audit modules come here in right sequence --
        audit_report = []

        # TODO(kris) have the report file grow during the audit would be nice

        if 'fwaas' in self.resource or 'all' in self.resource:
            from nuage_openstack_audit.fwaas.fwaas_audit import FWaaSAudit
            FWaaSAudit(neutron, vsd).audit(audit_report)

        # -- end --

        self.end_report(report_file, audit_report)

        INFO.h0('Audit complete in %d secs', int(time.time() - start_time))
        return audit_report

    @staticmethod
    def create_os_client():
        from nuage_openstack_audit.osclient.osclient import OSClient
        return OSClient()

    def create_vsd_client(self):
        from nuage_openstack_audit.vsdclient.vsdclient import VsdClient

        user, password = Utils.get_env_var('OS_VSD_SERVER_AUTH',
                                           'csproot:csproot').split(':')
        return VsdClient(
            vsd_server=Utils.get_env_var('OS_VSD_SERVER'),
            user=user,
            password=password,
            base_uri=Utils.get_env_var('OS_VSD_BASE_URI', '/nuage/api/v5_0'),
            cms_id=Utils.get_env_var('OS_CMS_ID'),
            enterprise=Utils.get_env_var('OS_DEFAULT_NETPARTITION'))

    @staticmethod
    def expand_filename(dir_name, file_name, file_ext):
        dir_name = os.path.expanduser(dir_name)  # expand "~"
        dir_name = os.path.abspath(dir_name)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        if not file_name.endswith(file_ext):
            file_name += file_ext
        return '%s/%s_%s' % (dir_name, 'nuage_openstack_audit', file_name)

    def relative_filename(self, file_name):
        pwd = Utils.get_env_var('PWD', 'NOTONLINUX?')
        if file_name.startswith(pwd):
            file_name = '.' + file_name[len(pwd):]
        return file_name

    def init_logger(self, initiating_time):
        from nuage_openstack_audit.utils.logger import get_logger
        logger = get_logger()
        logger.set_verbose(self.verbose)

        env_set_level = Utils.get_env_var('OS_AUDIT_LOG_LEVEL', 'INFO').upper()
        level = 'DEBUG' if self.debug else env_set_level
        self.debug = level == 'DEBUG'  # possibly correcting initial setting,
        #                                based on env. log level setting

        log_dir = Utils.get_env_var('OS_AUDIT_LOG_DIR', '.')
        log_file = self.expand_filename(log_dir, initiating_time, '.log')

        logger.init_logging(level, log_file)
        USER.h0('Logfile created at %s', self.relative_filename(log_file))
        INFO.h0('Tracing is %s', level)

        return logger

    def prep_report_name(self, suffix='report'):
        report_dir = Utils.get_env_var(
            'OS_AUDIT_REPORT_DIR', '.')
        fixed_report_file = Utils.get_env_var(
            'OS_AUDIT_REPORT_FILE', '')
        return self.expand_filename(
            report_dir, fixed_report_file or suffix, '.json')

    def end_report(self, report_file, audit_report):
        USER.h1('Reporting %d discrepancies', len(audit_report))
        with open(report_file, 'w') as outfile:
            json.dump(audit_report, outfile, indent=4)
        USER.h0('Audit report written to %s',
                self.relative_filename(report_file))


def main():
    Main().run()


if __name__ == '__main__':
    main()
