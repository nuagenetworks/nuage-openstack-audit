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

3. Set up API access to neutron and VSD, using configuration environment
   variables as shown above.

   Below example is assuming environment variables are set in
   etc/nuage-openstack-audit.rc and an OpenStack env file (e.g. stackrc)

   .. code-block:: bash

      $ . etc/nuage-openstack-audit.rc
      $ . stackrc

4. Use:

   .. code-block:: bash

      $ nuage-openstack-audit -h

   for help.

5. Launch a FWaaS audit:

   .. code-block:: bash

      $ nuage-openstack-audit fwaas

6. Review the audit results. Any identified audit mismatch condition will be
   reflected in the generated audit report.

-----------
Limitations
-----------

The system under audit has to be API-write-silent during the audit operation,
or unpredictable audit results will occur.
