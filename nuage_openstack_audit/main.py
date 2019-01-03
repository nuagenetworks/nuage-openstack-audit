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

import argparse
import json
import os
import six
import time

from nuage_openstack_audit.utils.developer import DeveloperModus
from nuage_openstack_audit.utils.logger import Reporter
from nuage_openstack_audit.utils.utils import Utils

ERROR = Reporter('ERROR')
WARN = Reporter('WARN')
USER = Reporter('USER')
INFO = Reporter('INFO')
DEBUG = Reporter('DEBUG')

NUAGE_OPENSTACK_AUDIT_PREFIX = 'nuage_openstack_audit_'


class Main(object):

    program = 'nuage-openstack-audit'

    description = '''
    Nuage OpenStack Audit is auditing networking resources between
    OpenStack neutron and the Nuage Networks VCS platform.'''

    def __init__(self, args=None):

        # housekeeping & parse command line arguments
        self.initiating_time = time.strftime("%d-%m-%Y_%H:%M:%S")

        if not args:
            parser = argparse.ArgumentParser(prog=self.program,
                                             description=self.description)
            parser.add_argument('-v', '--verbose',
                                help='run with verbose output',
                                action="store_true")
            parser.add_argument('-d', '--debug',
                                help='log with debug level',
                                action="store_true")
            parser.add_argument('-o', '--report',
                                help='specify the report file',
                                default=None)
            parser.add_argument('resource', help='resources to audit',
                                choices=['fwaas', 'security_group', 'all'])
            args = parser.parse_args()

        self.developer_modus = self.check_developer_modus()
        self.debug = args.debug or self.developer_modus
        self.verbose = args.verbose
        self.extreme_verbose = (
            (hasattr(args, 'extreme_verbose') and
             args.extreme_verbose) or self.developer_modus)
        self.no_log = hasattr(args, 'no_log') and args.no_log
        self.report = args.report
        self.resource = args.resource

        # retrieve credential info from environment variables
        cms_id = self.get_cms_id()
        os_credentials = self.get_os_credentials()
        vsd_credentials = self.get_vsd_credentials()

        # init logging
        self.init_logger(self.initiating_time)

        # initialize and authenticate the clients
        USER.h1('Authenticating with OpenStack')
        os_credentials.report(DEBUG)
        self.neutron = self.get_neutron_client(os_credentials)

        USER.h1('Authenticating with Nuage VSD')
        vsd_credentials.report(DEBUG)
        self.cms_id = cms_id
        self.vsd = self.get_vsd_client(cms_id, vsd_credentials)

    def init_logger(self, initiating_time):
        from nuage_openstack_audit.utils.logger import get_logger
        logger = get_logger()
        logger.set_verbose(self.verbose)
        logger.set_extreme_verbose(self.extreme_verbose)

        env_set_level = Utils.get_env_var(
            'OS_AUDIT_LOG_LEVEL', 'INFO').upper()
        level = 'DEBUG' if self.debug else env_set_level
        self.debug = level == 'DEBUG'  # possibly correcting initial setting,
        #                                based on env. log level setting

        log_file = (self.expand_filename(
            Utils.get_env_var('OS_AUDIT_LOG_DIR', '.'),
            NUAGE_OPENSTACK_AUDIT_PREFIX + initiating_time, '.log')
            if not self.no_log else None)

        logger.init_logging(level, log_file)
        if log_file:
            USER.h0('Logfile created at %s', self.relative_filename(log_file))
        if self.developer_modus:
            WARN.report('Developer modus is on')
        return logger

    @staticmethod
    def get_cms_id():
        return Utils.get_env_var('OS_CMS_ID', required=True)

    @staticmethod
    def get_os_credentials():
        from nuage_openstack_audit.osclient.osclient import OSCredentials

        auth_url = Utils.get_env_var('OS_AUTH_URL', required=True)
        username = Utils.get_env_var('OS_USERNAME', required=True)
        project_name = Utils.get_env_var(
            'OS_PROJECT_NAME', Utils.get_env_var('OS_TENANT_NAME'))
        if not project_name:
            Utils.env_error('OS_PROJECT_NAME nor OS_TENANT_NAME '
                            'is defined. Please set either of both.')
        password = Utils.get_env_var('OS_PASSWORD', required=True)
        identity_api_version = float(  # deal with version '2.0' e.g.
            Utils.get_env_var('OS_IDENTITY_API_VERSION', 3))

        # add support to specify certificate verification
        # -- below is not a standard OS env setting -> documented in README --
        verify_ca = Utils.get_env_bool('OS_VERIFY_CA', True)
        # -- below is standard --
        ca_cert = Utils.get_env_var('OS_CACERT')
        # end of specify certificate verification

        user_domain_id = Utils.get_env_var('OS_USER_DOMAIN_ID')
        user_domain_name = Utils.get_env_var('OS_USER_DOMAIN_NAME')
        if not user_domain_name and not user_domain_id:
            Utils.env_error('OS_USER_DOMAIN_ID nor OS_USER_DOMAIN_NAME '
                            'is defined. Please set either of both.')
        project_domain_id = Utils.get_env_var('OS_PROJECT_DOMAIN_ID')
        project_domain_name = Utils.get_env_var('OS_PROJECT_DOMAIN_NAME')
        if not project_domain_name and not project_domain_id:
            Utils.env_error('OS_PROJECT_DOMAIN_ID nor OS_PROJECT_DOMAIN_NAME '
                            'is defined. Please set either of both.')

        return OSCredentials(
            auth_url, username, password, project_name, identity_api_version,
            verify_ca, ca_cert, user_domain_id, user_domain_name,
            project_domain_id, project_domain_name)

    @staticmethod
    def get_vsd_credentials():
        from nuage_openstack_audit.vsdclient.vsdclient import VsdCredentials
        user, password = Utils.get_env_var('OS_VSD_SERVER_AUTH',
                                           'csproot:csproot').split(':')
        return VsdCredentials(
            vsd_server=Utils.get_env_var('OS_VSD_SERVER', required=True),
            user=user,
            password=password,
            base_uri=Utils.get_env_var('OS_VSD_BASE_URI', '/nuage/api/v5_0'),
            enterprise=Utils.get_env_var('OS_DEFAULT_NETPARTITION',
                                         required=True))

    def audit_fwaas(self):
        from nuage_openstack_audit.fwaas.fwaas_audit import FWaaSAudit
        if not self.verbose:
            USER.h1('Auditing Firewalls')  # redundant when verbose
        return FWaaSAudit(self.neutron, self.vsd, self.cms_id).audit()

    def audit_sg(self):
        from nuage_openstack_audit.security_group.security_group_audit import \
            SecurityGroupAudit
        if not self.verbose:
            USER.h1('Auditing Security Groups')  # redundant when verbose
        return SecurityGroupAudit(self.neutron, self.vsd, self.cms_id).audit()

    def run(self):
        start_time = time.time()
        audit_report = []
        nbr_entities_in_sync = 0
        report_file = (self.report if self.report
                       else self.prep_report_name(self.initiating_time))

        # -- all audit modules come here in right sequence --
        if 'fwaas' in self.resource or 'all' in self.resource:
            fwaas_audit_report, fwaas_in_sync_cnt = self.audit_fwaas()
            audit_report += fwaas_audit_report
            nbr_entities_in_sync += fwaas_in_sync_cnt

        if 'security_group' in self.resource or 'all' in self.resource:
            sg_audit_report, sg_in_sync_cnt = self.audit_sg()
            audit_report += sg_audit_report
            nbr_entities_in_sync += sum(six.itervalues(sg_in_sync_cnt))
        # -- end --

        self.end_report(report_file, audit_report, nbr_entities_in_sync)

        INFO.h0('Audit complete in %d secs', int(time.time() - start_time))
        return audit_report, nbr_entities_in_sync

    @staticmethod
    def get_neutron_client(credentials):
        from nuage_openstack_audit.osclient.osclient import NeutronClient
        return NeutronClient().authenticate(credentials)

    @staticmethod
    def get_vsd_client(cms_id, credentials):
        from nuage_openstack_audit.vsdclient.vsdclient import VsdClient
        return VsdClient(cms_id).authenticate(credentials)

    @staticmethod
    def check_developer_modus():
        if Utils.get_env_bool('OS_AUDIT_DEVELOPER_MODUS'):
            DeveloperModus()
            return True
        else:
            return False

    @staticmethod
    def expand_filename(dir_name, file_name, file_ext):
        dir_name = os.path.expanduser(dir_name)  # expand "~"
        dir_name = os.path.abspath(dir_name)
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        if not file_name.endswith(file_ext):
            file_name += file_ext
        return '%s/%s' % (dir_name, file_name)

    @staticmethod
    def relative_filename(file_name):
        pwd = Utils.get_env_var('PWD')
        if pwd and file_name.startswith(pwd):
            file_name = '.' + file_name[len(pwd):]
        return file_name

    @staticmethod
    def prep_report_name(initiating_time):
        report_dir = Utils.get_env_var('OS_AUDIT_REPORT_DIR', '.')
        fixed_report_file = Utils.get_env_var('OS_AUDIT_REPORT_FILE')
        if not fixed_report_file:
            fixed_report_file = NUAGE_OPENSTACK_AUDIT_PREFIX + initiating_time
        return Main.expand_filename(report_dir, fixed_report_file, '.json')

    @staticmethod
    def end_report(report_file, audit_report, nbr_entities_in_sync):
        INFO.h1('Found %d entities in sync', nbr_entities_in_sync)
        USER.h1('Reporting %d discrepancies', len(audit_report))
        with open(report_file, 'w') as outfile:
            json.dump(audit_report, outfile, indent=4)
        USER.h0('Audit report written to %s',
                Main.relative_filename(report_file))


def main():
    audit_main = None
    try:
        audit_main = Main()
        audit_report, _ = audit_main.run()
        if not audit_report:
            return 0

    except Exception as e:
        if audit_main and audit_main.developer_modus:
            Utils.report_traceback(ERROR)
        else:
            ERROR.h0('ERROR: %s', e)

    # set exit code to 1 or error or when discrepancies found
    # -> allows for shell commands like:
    # $ nuage-openstack-audit all >/dev/null
    # $ if [[($? == 0)]]; then echo "OK"; else echo "NOK"; fi

    return 1


if __name__ == '__main__':
    exit(main())
