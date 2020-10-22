"""
title           : client_app.py
description     : Initialization of client
author          : Amanda Garcia-Garcia
date_created    : 11032020
date_modified   : 26082020
version         : 0
usage           : python server_api.py
python_version  : 3.6.1

"""

from flask_cors import CORS

from flask import Flask
from flask_restful import Api
from client.resources.client import *

app = Flask(__name__)
api = Api(app)
CORS(app=app, supports_credentials=True)


api.add_resource(Transaction, '/transaction') #GET = new wallet POST=generate_transaction



if __name__ == '__main__':
    from argparse import ArgumentParser

    #app = setup_app()

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
