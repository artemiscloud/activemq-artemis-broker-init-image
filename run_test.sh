#!/bin/bash

pushd script/cfg
python -m unittest security_config_test.py
popd > /dev/null

