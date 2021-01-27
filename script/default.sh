#!/bin/bash

#this script is looking for a custom
#script. If it exists it calls it for
#configuration. It not do nothing.

CUSTOM_CFG=/amq/scripts/post-config.sh
echo "exposing env var CONFIG_INSTANCE_DIR for custom init"
echo "CONFIG_INSTANCE_DIR value from ${CONFIG_INSTANCE_DIR}"
export CONFIG_INSTANCE_DIR=${CONFIG_INSTANCE_DIR}/${AMQ_NAME}
echo "Exported value of CONFIG_INSTANCE_DIR: ${CONFIG_INSTANCE_DIR}"
echo "Finding default custom script at ${CUSTOM_CFG}"
if [ -f "${CUSTOM_CFG}" ]; then
    echo "Found custom script ${CUSTOM_CFG}, executing it"
    ls ${CUSTOM_CFG}
    ${CUSTOM_CFG}
fi
