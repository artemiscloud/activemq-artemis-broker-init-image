#!/bin/bash

# this script configurs the security for broker
# The following env vars are available:
# SECURITY_CFG_YAML - The security yaml from cr
# CONFIG_INSTANCE_DIR - The instance dir
# YACFG_PROFILE_NAME - yacfg profile name, either 'artemis' or 'amq_broker'
# YACFG_PROFILE_VERSION - the profile version

echo "Configuring security from CR ${SECURITY_CFG_YAML}"
echo "yacfg name: ${YACFG_PROFILE_NAME}"
echo "yacfg version: ${YACFG_PROFILE_VERSION}"

python3 /opt/amq-broker/script/cfg/yacfg_tune_gen.py

echo "Done!"
