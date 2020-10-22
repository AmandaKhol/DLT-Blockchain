"""
title           : initialize.py
description     : Initialization of nodes network
author          : Amanda Garcia-Garcia
date_created    : 11032020
date_modified   : 04082020
version         : 0
usage           : python initialize.py
python_version  : 3.6.1

"""

import requests


list_nodes = {"nodes": "http://127.0.0.1:5002, http://127.0.0.1:5001"}
list_nodes_2 = {"nodes": "http://127.0.0.1:5002"}
init_blockchain = {'existing_blockchain': 'False'}

json_blockchain = init_blockchain
json_nodes = list_nodes

requests.post('http://127.0.0.1:5000/teresa', json=json_blockchain)
requests.post('http://127.0.0.1:5000/teresa/nodes', json=json_nodes)

