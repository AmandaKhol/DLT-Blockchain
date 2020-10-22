"""
title           : client.py
description     : Model of the client
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

from collections import OrderedDict


import binascii

from Crypto.Hash import SHA256, SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5, pss, PKCS1_PSS


class TransactionModel():
    
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
        key = RSA.import_key(binascii.unhexlify(self.sender_private_key))
        mensaje = str(self.to_dict()).encode('utf8')
        h = SHA256.new(mensaje)
        signature = PKCS1_PSS.new(key).sign(h)
        return binascii.hexlify(signature).decode('ascii')