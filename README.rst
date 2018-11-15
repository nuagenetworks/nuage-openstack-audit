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
clients are set up, by defining OS\_ environmental variables.

VSD API access is specified using environmental variables as sample-specified
in

   etc/nuage-openstack-audit.sample.rc

---
Use
---

0. Ensure system running audit has a working Python 2.7 environment, and has access to a current PyPi mirror for install of dependencies.

1. Install the nuage-openstack-audit package. E.g. by

    $ virtualenv venv

    $ . venv/bin/activate

    $ pip install <delivered .whl file>

2. Set up API access to neutron and VSD, as highlighted above. e.g.

    $ source etc/nuage-openstack-audit.rc
    $ source stackrc

3. Use:

    nuage-openstack-audit -h

   for help.

4. Launch a FWaaS audit:

    nuage-openstack-audit fwaas

5. Review results. Any identified audit mismatch condition will be reflected in the generated audit report.

-----------
Limitations
-----------

The system under audit has to be API-write-silent during the audit
operation, or unpredictable audit results will occur.
