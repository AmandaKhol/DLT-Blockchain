"""
title           : node.py
description     : Model of the node
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""


import Crypto
import binascii

from db import db

from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5, PKCS1_PSS

from flask import request



NodeBlockchain = db.Table('nodes_blockchains',
                              db.Column('id', db.Integer, primary_key=True),
                              db.Column('node_id', db.Integer, db.ForeignKey('nodes.id')),
                              db.Column('blockchain_id', db.Integer,
                                        db.ForeignKey('blockchains.id_blockchain')))

class NodeModel(db.Model):
    __tablename__ = 'nodes'

    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String, nullable=False)
    #password = db.Column(db.String)
    nonce_challenge = db.Column(db.String)
    challenge_created = db.Column(db.Boolean)
    node_token = db.Column(db.String)
    node_refresh_token = db.Column(db.String)

    node_private_key = db.Column(db.String)
    node_public_key = db.Column(db.String)

    blockchains = db.relationship("BlockchainModel", secondary=NodeBlockchain,
                                  backref=db.backref('nodesin', lazy='dynamic'))


    def create_key_pair(self):
        random_gen = Crypto.Random.new().read
        node_private_key = RSA.generate(1024, random_gen)
        node_public_key = node_private_key.publickey()

        self.node_public_key = binascii.hexlify(node_public_key.exportKey(format='DER')).decode('ascii')
        self.node_private_key = binascii.hexlify(node_private_key.exportKey(format='DER')).decode('ascii')


    def sign_response(self, response):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.node_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(response).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def find_by_ip(cls, _ip):
        return cls.query.filter_by(ip=_ip).first()

    @classmethod
    def find_by_public_key(cls, node_public_key):
        return cls.query.filter_by(node_public_key=node_public_key).first()


    @classmethod
    def nodes_in_a_blockchain_2(cls, blockchain_name):
        result = db.session.query(cls.ip).filter(cls.blockchains.any(blockchain_name=blockchain_name)).all()
        message = {'nodes': [ips[0] for ips in result]}
        return message

    @classmethod
    def verify_public_key(cls, node_public_key):
        query_result = cls.query.filter_by(node_public_key=node_public_key).first()
        if query_result is None:
            return False
        else:
            return True

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()



