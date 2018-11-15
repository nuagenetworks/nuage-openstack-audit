=====================
Nuage OpenStack Audit
=====================

A smart auditing tool for Nuage-OpenStack deployments.

-----
Scope
-----

Nuage OpenStack Audit is auditing networking resources between
OpenStack neutron and the Nuage Networks VCS platform.
At both sides it requires API access, i.e.

- keystone and neutron access at OpenStack side
- VSD API access at Nuage VCS side.

Keystone/Neutron access is set up in same way as python keystone/neutron
clients are set up, by defining standard OpenStack OS\_* environment variables.

VSD API access and audit tool configuration is specified using environment 
variables as specified in the sample in:

.. code-block:: bash

     etc/nuage-openstack-audit.sample.rc

---
Use
---

1. Ensure system running audit has a working Python 2.7 environment, and has 
   access to a current PyPi mirror for install of dependencies.

2. Install the nuage-openstack-audit package. e.g.

   .. code-block:: bash

        $ virtualenv nuage-audit
        $ . ~/nuage-audit/bin/activate
        $ pip install <delivered .whl file>

3. Set up API access to neutron and VSD, using configuration environment variables as shown above. Example
   assuming environment variables are set in etc/nuage-openstack-audit.rc and 
   an OpenStack env file (e.g. stackrc)

   .. code-block:: bash

      $ source etc/nuage-openstack-audit.rc
      $ source stackrc

4. Use:

   .. code-block:: bash
   
      $ nuage-openstack-audit -h

   for help.

5. Launch a FWaaS audit:

   .. code-block:: bash

      $ nuage-openstack-audit fwaas

6. Review results in report file as well as any logs. Any identified audit mismatch condition will be reflected in the generated audit report.

-----------
Limitations
-----------

The system under audit has to be API-write-silent during the audit
operation, or unpredictable audit results will occur.
