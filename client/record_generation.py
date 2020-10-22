"""
title           : record_generation.py
description     : Class of a record. Methods of the record
author          : Amanda Garcia-Garcia
date_created    : 11032020
date_modified   : 26082020
version         : 0
usage           : python server_api.py
python_version  : 3.6.1

"""

import binascii
from collections import OrderedDict

import Crypto

from flask import jsonify, request, make_response

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


class Record():
    def __init__(self, sender_address, sender_private_key, record_data):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.record_data = record_data

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'record_data': self.record_data})

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

def generate_key_pair():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        "private_key": binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        "public_key": binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }

    return make_response(jsonify(response), 200)

def generate_record():
    #si fuera de un formulario: request.form
    sender_address = request.json['sender_address']
    sender_private_key = request.json['sender_private_key']
    blockchain_name = request.json['blockchain_name']
    record_data = request.json['record_data']

    record = Record(sender_address, sender_private_key, record_data)
    signature = record.sign_transaction()

    response = {'record': record.to_dict(),
                'blockchain_name': blockchain_name,
                'signature': signature,
                }


    return make_response(jsonify(response), 200)


def request_to_dict(sender_address, record_data, signature):
    return OrderedDict({'sender_address': sender_address,
                        'record_data': record_data,
                        'signature': signature})
