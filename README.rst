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

Install the nuage-openstack-audit package.

Set up API access to neutron and VSD.

Give:

    nuage-openstack-audit [-h|--help]

for help.

Launch a FWaaS audit:

    nuage-openstack-audit fwaas

-----------
Limitations
-----------

The system under audit has to be API-write-silent during the audit
operation.
