#!/bin/bash

# Copyright 2015 Alcatel-Lucent USA Inc.
#
# All Rights Reserved
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

function create_or_retrieve_cms {
    # If NUAGE_VSD_CMS_ID is not set, find or create a cms on VSD.
    if [[ -z "$NUAGE_VSD_CMS_ID" ]]; then
        username=$( echo "${NUAGE_VSD_SERVER_AUTH}" | cut -d ':' -f 1)

        upper_ssl=${NUAGE_VSD_SERVER_SSL^^}
        if [[ "$upper_ssl" = "TRUE" ]]; then
            base_url="https://"
        else
            base_url="http://"
        fi
        base_url+="$NUAGE_VSD_SERVERS"
        base_url+="$NUAGE_VSD_BASE_URI"
        url="$base_url$NUAGE_VSD_AUTH_RESOURCE"

        echo "Connecting to VSD"
        result=$(curl --request GET --insecure --silent --header "Content-Type: application/json" --header "X-Nuage-Organization: $NUAGE_VSD_ORGANIZATION" --user "$NUAGE_VSD_SERVER_AUTH" "$url")
        regex='"APIKey":.?"([^"]*)"'
        [[ ${result} =~ $regex ]]
        apikey="${BASH_REMATCH[1]}"
        echo "Connected"

        mac=`cat /sys/class/net/eth0/address`
        name="OPENSTACK_$mac"
        url="$base_url/cms"

        echo "Trying to find CMS with name: $name"
        result=$(curl --request GET --insecure --silent --header "Content-Type: application/json" --header "X-Nuage-Organization: $NUAGE_VSD_ORGANIZATION" --user "$username:$apikey" "$url")
        regex=".*(\{[^\}]*\"name\":.?\"$name\"[^\}]*\}).*"
        if [[ ${result} =~ $regex ]]; then
            cms="${BASH_REMATCH[1]}"
            regex='"ID":.?"([^"]*)"'
            if [[ ${cms} =~ $regex ]]; then
                NUAGE_VSD_CMS_ID="${BASH_REMATCH[1]}"
            fi
        fi

        if [[ ${NUAGE_VSD_CMS_ID} ]]; then
            echo "Found CMS: $NUAGE_VSD_CMS_ID"
        else
            echo "Could not find existing CMS with name: $name"
            echo "Creating CMS"
            result=$(curl --request POST --insecure --silent --header "Content-Type: application/json" --header "X-Nuage-Organization: $NUAGE_VSD_ORGANIZATION" --user "$username:$apikey" "$url" --data "{\"name\":\"$name\"}")
            regex='"ID":.?"([^"]*)"'
            [[ ${result} =~ $regex ]]
            NUAGE_VSD_CMS_ID="${BASH_REMATCH[1]}"
            echo "Created CMS with id: $NUAGE_VSD_CMS_ID"
        fi
    fi
    eval "$1=${NUAGE_VSD_CMS_ID}"
}

function configure_tempest_nuage_audit {
    iniset $TEMPEST_CONFIG nuage_openstack_audit nuage_vsd_server $NUAGE_VSD_SERVERS
    iniset $TEMPEST_CONFIG nuage_openstack_audit nuage_base_uri $NUAGE_VSD_BASE_URI
    iniset $TEMPEST_CONFIG nuage_openstack_audit nuage_auth_resource $NUAGE_VSD_AUTH_RESOURCE
    iniset $TEMPEST_CONFIG nuage_openstack_audit nuage_vsd_org $NUAGE_VSD_ORGANIZATION
    iniset $TEMPEST_CONFIG nuage_openstack_audit nuage_vsd_user ${NUAGE_VSD_SERVER_AUTH%:*}
    iniset $TEMPEST_CONFIG nuage_openstack_audit nuage_vsd_password ${NUAGE_VSD_SERVER_AUTH#*:}
    iniset $TEMPEST_CONFIG nuage_openstack_audit nuage_default_netpartition $NUAGE_VSD_DEF_NETPART_NAME
    create_or_retrieve_cms cms_id
    iniset $TEMPEST_CONFIG nuage_openstack_audit nuage_cms_id $cms_id
    iniset $TEMPEST_CONFIG nuage_openstack_audit mysql_password $DATABASE_PASSWORD
}

function install_test_requirements {
    echo_summary "Installing test requirements "$AUDIT_TEMPEST_DIR" with upper constraints from '"$REQUIREMENTS_DIR"'"
    tox -evenv-tempest -- pip install -r $AUDIT_TEMPEST_DIR/test-requirements.txt -c $REQUIREMENTS_DIR/upper-constraints.txt
}

if [[ "$1" == "stack" ]]; then
    if [[ "$2" == "install" ]]; then
        echo_summary "Installing requirements "$AUDIT_TEMPEST_DIR
        pip_install -r $AUDIT_TEMPEST_DIR/requirements.txt -e $AUDIT_TEMPEST_DIR
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        configure_tempest_nuage_audit
    elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        configure_tempest_nuage_audit
        install_test_requirements
    fi
elif [[ "$1" == "unstack" ]]; then
        # no-op
        :
fi

