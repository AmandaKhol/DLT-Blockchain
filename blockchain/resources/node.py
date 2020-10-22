"""
title           : node.py
description     : Resource of the node
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

import requests
import binascii
import uuid

from flask_restful import Resource
from flask import request
from flask_jwt_extended import create_access_token, create_refresh_token

from werkzeug.security import safe_str_cmp

from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5, PKCS1_PSS

from blockchain.models.node import NodeModel

from blockchain.schemas.node import NodeSchema

node_schema = NodeSchema()


class NodeRegister(Resource):
    @classmethod
    def post(cls):
        # try:
        json = request.get_json()
        node_data = node_schema.load(json)

        if NodeModel.find_by_ip(node_data.ip):
            return {"message": "A user with that IP address already exists"}, 400

        node = NodeModel(ip=node_data.ip)
        node.node_public_key = node_data.node_public_key
        node.challenge_created = False
        node.save_to_db()

        # intercambio de tokens
        self_node = NodeModel.find_by_ip(request.environ['HTTP_HOST'])
        register_credentials = {
            'ip': self_node.ip,
            'node_public_key': self_node.node_public_key
        }
        requests.post('http://' + node_data.ip + '/register', json=register_credentials)

        login_credentials = {
            'ip': self_node.ip
        }
        result = requests.post('http://' + node_data.ip + '/login', json=login_credentials)
        challenge_response = result.json()['challenge']
        signature = self_node.sign_response(challenge_response)
        login_response = {
            'ip': self_node.ip,
            'response': challenge_response,
            'signature': signature
        }

        save_tokens = requests.post('http://' + node_data.ip + '/login', json=login_response)
        if save_tokens.status_code == 200:
            node_access = NodeModel.find_by_ip(node_data.ip)
            #almacenamos el token asociado a ese nodo
        # if safe_str_cmp(save_tokens.json()['node_public_key'], node_access.node_public_key):
            node_access.node_token = save_tokens.json()['access_token']
            node_access.node_refresh_token = save_tokens.json()['refresh_token']
            node_access.save_to_db()

            return {"message": "User logged successfully."}, 200

        return {"message": "User created successfully"}, 201


class NodeLogin(Resource):
    @classmethod
    def post(cls):
        node_data = request.get_json()
        node = NodeModel.find_by_ip(node_data['ip'])

        if 'response' not in node_data:
            challenge = create_challenge(node_data['ip'])
            node.challenge_created = True
            node.save_to_db()
            return {
                'challenge': challenge
            }, 200

        if 'signature' not in node_data:
            return {
                'message': 'Credentials missed'
            }, 404

        if node_data['response'] and node.challenge_created:
            valid_signature = check_signature(node_data['response'], node.node_public_key, node_data['signature'])
            if valid_signature and safe_str_cmp(node.nonce_challenge, node_data['response']):
                access_token = create_access_token(identity=node.id, fresh=False)
                refresh_token = create_refresh_token(node.id)
                node.challenge_created = False
                node.nonce_challenge = 0
                node.save_to_db()

                return {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    # 'node_public_key': NodeModel.find_by_ip(request.environ['HTTP_HOST']).node_public_key
                }, 200

        return {"message": "invalid credentials"}, 401


def create_challenge(node_ip):
    #su public key mas el caracter 5
    node = NodeModel.find_by_ip(node_ip)
    challenge = uuid.uuid4().hex + uuid.uuid1().hex
    node.nonce_challenge = challenge
    node.save_to_db()
    return challenge

def check_signature(node_response, node_public_key, signature):
    node_public_key = RSA.importKey(binascii.unhexlify(node_public_key))
    mensaje = node_response
    verifier = PKCS1_v1_5.new(node_public_key)
    h = SHA.new(str(mensaje).encode('utf8'))
    return verifier.verify(h, binascii.unhexlify(signature))


