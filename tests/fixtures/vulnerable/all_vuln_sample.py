import hashlib
import os
import pickle
import subprocess
import tempfile

import yaml


def demo_all_vulnerabilities(user_input, data, doc):
    os.system(user_input)
    subprocess.run(user_input, shell=True)
    eval("2 + 2")
    pickle.loads(data)
    yaml.load(doc)
    tempfile.mktemp()
    hashlib.md5(data)
    hashlib.sha1(data)
    hashlib.new("md5", data)
