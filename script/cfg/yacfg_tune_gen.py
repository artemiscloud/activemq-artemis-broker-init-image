import yaml
from pathlib import Path
from io import StringIO
import json
import os
import re
import shutil
from collections import OrderedDict
import urllib.request
import apply_security


INDENT_2 = '  '


def list_my_dir(targetdir):
    results = os.listdir(targetdir)
    print("files under dir", targetdir)
    for item in results:
        print(item)


if __name__ == '__main__':
    inst_dir = os.environ['CONFIG_INSTANCE_DIR']
    amq_name = os.environ['AMQ_NAME']
    broker_dir = inst_dir + "/" + amq_name

    config_cr_file = os.getenv('SECURITY_CFG_YAML')
    the_context = apply_security.ConfigContext(Path(broker_dir).absolute())
    the_context.parse_config_cr(config_cr_file)
    print("now apply changes...")
    the_context.apply()
