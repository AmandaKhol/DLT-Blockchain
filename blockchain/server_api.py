"""
title           : server_api.py
description     : Initialization of nodes network
author          : Amanda Garcia-Garcia
date_created    : 11032020
date_modified   : 26082020
version         : 0
usage           : python server_api.py
python_version  : 3.6.1

"""



import datetime

from flask import Flask, jsonify
from flask_restful import Api
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from marshmallow import ValidationError

from blockchain.db import db
from blockchain.resources.blockchain import *
from blockchain.resources.node import *

from ma import ma


app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_AUTH_USERNAME_KEY'] = 'ip'
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(seconds=20) #15 min
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(seconds=10) #15 min
app.secret_key = 'amanda1'
CORS(app=app, supports_credentials=True)
api = Api(app)

# app.config['JWT_AUTH_URL_RULE'] = '/login'
# jwt = JWT(app, authenticate, identity)

# jwt = JWT(app, authenticate, identity) #/auth
jwt = JWTManager(app)

@app.errorhandler(ValidationError)
def handle_marshmallow_validation(err): #except ValidatiorError as err
	return jsonify(err.messages), 400


@app.before_first_request
def create_tables():
    db.create_all()

api.add_resource(Blockchain, '/<string:blockchain_name>')
api.add_resource(BlockchainNodes, '/<string:blockchain_name>/nodes')
api.add_resource(BlockchainRecords, '/<string:blockchain_name>/records')
api.add_resource(BlockchainChain, '/<string:blockchain_name>/chain')
api.add_resource(NodeRegister, '/register')
api.add_resource(NodeLogin, '/login')


api.add_resource(TestApi, '/testapi')


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    host = '127.0.0.1'  # solo escucha a mi dirección local. Si fuera 0.0.0.0 seria a cualquier IP

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data' + str(port) + '.db'

    db.init_app(app)
    ma.init_app(app)

    app.run(host=host, port=port)

