=====================
Nuage OpenStack Audit
=====================

A smart auditing tool for Nuage OpenStack deployments.

-----
Scope
-----

Nuage OpenStack Audit is auditing networking resources between
OpenStack Neutron and the Nuage Networks VCP platform.
At both sides it requires API access, i.e.

- keystone and neutron access at OpenStack side as an `admin` user with access
  to `admin` tenant
- VSD API access at Nuage VCS side with `CSP Root Group` privileges

Keystone/Neutron access is set up in same way as python keystone/neutron
clients are set up, by defining standard OpenStack OS\_* environment variables.

Next to the standard variables, one can set OS_VERIFY_CA variable to True or
False for enabling certificate verification in the SSL communication to
OpenStack. Defaults to True when not set.
Note this aligns with the OS client --verify setting.
Only when set to True, standard variable OS_CACERT will be considered by Audit.

VSD API access and audit tool configuration is specified using environment
variables as specified in the sample file `etc/nuage-openstack-audit.sample.rc`

---
Use
---

1. Ensure the system running the audit has a working Python 2.7 environment,
   and has access to a current PyPi mirror to install dependencies.

2. Install the nuage-openstack-audit package. e.g.

   .. code-block:: bash

      $ virtualenv nuage-audit
      $ . ~/nuage-audit/bin/activate
      $ pip install <delivered .whl file>

   When upgrading to a new version, pip install the newer .whl file in the
   existing environment.

3. Set up API access to neutron and VSD, using configuration environment
   variables as shown above.

   Below example is assuming environment variables are set in
   etc/nuage-openstack-audit.rc and an OpenStack env file (e.g. stackrc)

   .. code-block:: bash

      $ . etc/nuage-openstack-audit.rc
      $ . stackrc

4. Use command line argument '--help' for help:

   .. code-block:: bash

      $ nuage-openstack-audit --help

        usage: nuage-openstack-audit [-h] [-v] [-d] [-o REPORT] [-p PROJECT]
                                     {fwaas,security_group,all}

        Nuage OpenStack Audit is auditing networking resources between OpenStack
        neutron and the Nuage Networks VCS platform.

        positional arguments:
          {fwaas,security_group,all}
                                resources to audit

        optional arguments:
          -h, --help            show this help message and exit
          -v, --verbose         run with verbose output
          -d, --debug           log with debug level
          -o REPORT, --report REPORT
                                specify the report file
          -p PROJECT, --project PROJECT
                                Project ID of the project to be audited. Only
                                resources of this project will be audited. This
                                parameter is optional.

5. Run audit:

   The following three use cases are supported:

   * audit only FWaaS entities

     .. code-block:: bash

        $ nuage-openstack-audit fwaas

   * audit only security group entities

     .. code-block:: bash

        $ nuage-openstack-audit security_group

   * audit both FWaaS and security group entities

     .. code-block:: bash

        $ nuage-openstack-audit all

   * Audit only the resources for a specific project using the --project
     <project-id> argument, where project-id is the ID of the project
     to be audited. Auditing a specific project requires the executing user
     to be an admin with access to the audited project. E.g.:

      .. code-block:: bash

         $ nuage-openstack-audit all --project 6082963e62194580ab79bd596b6aeb6a



6. Review the audit results. Any identified audit mismatch condition will be
   reflected in the generated audit report.  The audit report will be written
   to the working directory by default. Alternatively, pass the '-o' or
   '--report' option to specify an output file.

-----------
Limitations
-----------

The system under audit has to be API-write-silent during the audit operation,
or unpredictable audit results will occur.
