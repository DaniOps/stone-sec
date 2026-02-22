import ftplib
import hashlib
import httpx
import joblib
import jsonpickle
import marshal
import numpy as np
import os
import pandas as pd
import pickle
import requests
import ssl
import subprocess
import telnetlib
import tempfile
import torch
import yaml


def trigger_all_rules(user_input, data, doc, url, host):
    eval("2 + 2")
    exec("print('x')")
    os.system(user_input)
    subprocess.run(user_input, shell=True)
    pickle.loads(data)
    yaml.load(doc)
    yaml.full_load(doc)
    tempfile.mktemp()
    hashlib.md5(data)
    hashlib.sha1(data)
    hashlib.new("md5", data)
    marshal.loads(data)
    jsonpickle.decode(data)
    np.load(data, allow_pickle=True)
    pd.read_pickle(data)
    torch.load(data)
    joblib.load(data)
    requests.get(url, verify=False)
    httpx.post(url, verify=False)
    ssl._create_unverified_context()
    telnetlib.Telnet(host)
    ftplib.FTP(host)
