"""
title           : blockchain.py
description     : Model of the blockchain
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

import hashlib
import json
import time
import binascii
import requests

from urllib.parse import urlparse
from collections import OrderedDict

from flask import request

from Crypto.Hash import SHA256, SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

from db import db

from blockchain.models.node import NodeModel
from blockchain.models.user import UserModel
from blockchain.models.block import BlockModel
from blockchain.models.record import RecordModel


MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
#0 = si quitamos el paquete de premio
# 2 = si añadimos el paquete de premio
MINING_DIFFICULTY = 0



class BlockchainModel(db.Model):

    __tablename__ = 'blockchains'

    __table_args__ = {'extend_existing': True}


    id_blockchain = db.Column(db.Integer, primary_key=True)
    blockchain_name = db.Column(db.String(10), nullable=False)

    blocks = db.relationship('BlockModel', lazy='dynamic')


    def __init__(self, blockchain_name):
        self.blockchain_name = blockchain_name
        self.records = []
        self.chain = []
        self.nodes = set()

    def __repr__(self):
        return '<Blockchain %r>' % self.blockchain_name

    def nodes_in(self):
        return [node.ip for node in self.nodesin]


    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id_blockchain=_id).first()

    @classmethod
    def find_by_name(cls, name):
        return cls.query.filter_by(blockchain_name=name).first()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


    def register_node(self, node_url, node_public_key):
        """
        Add a new node to the list of nodes
        """
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
            url = parsed_url.netloc
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
            url = parsed_url.path
        else:
            raise ValueError('Invalid URL')

        blockchain_db = BlockchainModel.find_by_name(self.blockchain_name)
        blockchain_nodes = blockchain_db.nodes_in()


        if NodeModel.find_by_ip(url) is None:
            self_node = NodeModel.find_by_ip(request.environ['HTTP_HOST'])
            self_credentials = {
                'ip': self_node.ip,
                'node_public_key': self_node.node_public_key
            }
            result = requests.post(node_url + '/register', json=self_credentials)


        if url not in blockchain_nodes:
             new_node_add = NodeModel.find_by_ip(url)
             blockchain_db.nodesin.append(new_node_add)
             db.session.commit()


    def submit_record(self, sender_address, record_data, signature):
        """
        Add a record to records array if the signature verified
        """
        record = OrderedDict({'sender_address': sender_address, 'record_data': record_data})

        new_user = UserModel(public_key=sender_address)
        if new_user.find_by_public_key(sender_address) is None:
            new_user.save_to_db()

        # Reward for mining a block
        if sender_address == MINING_SENDER:
            self.records.append(record)
            return len(self.chain) + 1
        # Manages records from wallet to another wallet
        else:
            record_verification = self.verify_record_signature(sender_address, signature, record)
            if record_verification:
                self.records.append(record)
                return len(self.chain) + 1
            else:
                return False

    def verify_record_signature(self, sender_address, signature, record):
        """
        Check that the provided signature corresponds to record
        signed by the public key (sender_address)
        """
        key = RSA.import_key(binascii.unhexlify(sender_address))
        mensaje = str(record).encode('utf8')
        h = SHA256.new(mensaje)
        verifier = PKCS1_PSS.new(key)
        sign = (binascii.unhexlify(signature))
        return verifier.verify(h, sign)



    def create_block(self, nonce, previous_hash):
        """
        Add a block of records to the blockchain
        """

        block = {'block_number': len(self.chain) + 1,
                 'time_stamp': time.time(),
                 'records': self.records,
                 'nonce': nonce,
                 'previous_hash': previous_hash}

        # Reset the current list of records
        self.records = []
        self.chain.append(block)

        return block

    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.records, last_hash, nonce) is False:
            nonce += 1

        return nonce

    def valid_proof(self, records, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        guess = (str(records) + str(last_hash) + str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def valid_chain(self, chain):
        """
        check if a bockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # print(last_block)
            # print(block)
            # print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            # Delete the reward record
            records = block['records'][:-1]
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            record_elements = ['sender_address', 'record_data']
            records = [OrderedDict((k, record[k]) for k in record_elements) for record in
                            records]

            if not self.valid_proof(records, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True


    def resolve_conflicts(self, blockchain_name):
        """
                Resolve conflicts between blockchain's nodes
                by replacing our chain with the longest one in the network.
                """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            not_node = request.environ['HTTP_HOST']
            if not node == not_node:
                # print('http://' + node + "/" + str(blockchain_name) + '/chain')
                response = requests.get('http://' + node + "/" + str(blockchain_name) + '/chain')
                # values = blockchain_schema.load(response.json())

                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    # Check if the length is longer and the chain is valid
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            id_blockchain_new = BlockchainModel.find_by_name(self.blockchain_name).id_blockchain

            for block in self.chain:
                new_block_number = block
                if block['block_number'] > max_length-1:
                    new_block_model = BlockModel(block_num=block['block_number'],
                                                 previous_hash=block['previous_hash'],
                                                 time_stamp=block['time_stamp'],
                                                 id_blockchain=id_blockchain_new,
                                                 nonce=block['nonce'])
                    new_block_model.save_to_db()

                # copiar los records
                    for record in block['records']:
                        new_user = UserModel(public_key=record['sender_address'])
                        if new_user.find_by_public_key(record['sender_address']) is None:
                            new_user.save_to_db()

                        record_id_user = UserModel.find_by_public_key(record['sender_address'])
                        new_record_model = RecordModel(record_data=record['record_data'],
                                                            id_user=record_id_user.id_user,
                                                            id_block=block['block_number'])
                        new_record_model.save_to_db()

            return True

        return False


def dict_to_binary(the_dict):
    str = json.dumps(the_dict)
    binary = ' '.join(format(ord(letter), 'b') for letter in str)
    return binary

