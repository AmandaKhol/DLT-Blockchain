"""
title           : client.py
description     : Resource of the client
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

import binascii
from collections import OrderedDict

import Crypto

from Crypto.PublicKey import RSA

from flask_restful import Resource
from flask import jsonify, request, make_response

from client.models.client import TransactionModel

class Transaction(Resource):

    #generates a new wallet
    def get(self):
        random_gen = Crypto.Random.new().read
        private_key = RSA.generate(1024, random_gen)
        public_key = private_key.publickey()
        response = {
            "private_key": binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
            "public_key": binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
        }
        return make_response(jsonify(response), 200)


    #generate de transaction
    def post(self):
        #si fuera de un formulario: request.form
        sender_address = request.json['sender_address']
        sender_private_key = request.json['sender_private_key']
        blockchain_name = request.json['blockchain_name']
        record_data = request.json['record_data']

        transaction = TransactionModel(sender_address, sender_private_key, record_data)
        signature = transaction.sign_transaction()

        response = {'transaction': transaction.to_dict(),
                    'blockchain_name': blockchain_name,
                    'signature': signature,
                    }
        return make_response(jsonify(response), 200)


def request_to_dict(sender_address, record_data, signature):
    return OrderedDict({'sender_address': sender_address,
                        'record_data': record_data,
                        'signature': signature})