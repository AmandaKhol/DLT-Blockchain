"""
title           : blockchain.py
description     : Resource of the blockchain
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""
from flask_restful import Resource
from flask import request, jsonify
from werkzeug.security import safe_str_cmp

from blockchain.models.block import BlockModel
from blockchain.models.blockchain import BlockchainModel

from flask_jwt_extended import jwt_required

import re
import requests
import time

from db import db


from blockchain.models.node import NodeModel
from blockchain.models.record import RecordModel
from blockchain.models.user import UserModel

from blockchain.schemas.blockchain import BlockchainSchema
from blockchain.schemas.node import NodeSchema
from blockchain.schemas.block import BlockSchema


list_blockchains = []
time_new_block = time.time() #control del consenso
waiting = False #variable de espera a tener la cadena actualizada

blockchain_schema = BlockchainSchema()
node_schema = NodeSchema()
block_schema = BlockSchema()

MIN_ACCEPT = 2

class Blockchain(Resource):


    def get(self, blockchain_name):
        blockchain = BlockchainModel.find_by_name(blockchain_name)
        if blockchain is None:
            return {'message': 'blockchain not found'}, 404
        # mensaje = blockchain.json()
        mensaje = blockchain_schema.dump(blockchain)
        return mensaje, 200

    # create_new_blockchain
    def post(self, blockchain_name):

        if not blockchain_name.strip():
            return 'Missing values', 400
        # forbidden characters
        if not re.match("^[A-Za-z0-9_]*$", blockchain_name):
            return 'The name of the blockchain must only contains letters, numbers, underscores and dashes', 400
        if BlockchainModel.find_by_name(blockchain_name):
            return {"message": "This blockchain '{}' already exists".format(blockchain_name)}, 400


        new_blockchain = BlockchainModel(blockchain_name)

        new_blockchain_model = BlockchainModel(blockchain_name)
        list_blockchains.append(new_blockchain)

        new_blockchain_model.save_to_db()

        # Save the genesis block in the database
        if request.json['existing_blockchain'] == 'False':
            new_blockchain_model_loop = BlockchainModel.find_by_name(blockchain_name)
            genesis = new_blockchain_model_loop.create_block(0, '00')

            new_blockchain.chain.append(genesis)
            new_blockchain_model_loop.save_to_db()

            block_genesis = new_blockchain_model.chain[0]

            block_genesis_model = BlockModel(block_num=block_genesis['block_number'],
                                             previous_hash=block_genesis['previous_hash'],
                                             time_stamp=block_genesis['time_stamp'],
                                             id_blockchain=new_blockchain_model.id_blockchain,
                                             nonce=block_genesis['nonce'])
            block_genesis_model.save_to_db()

        self_node = NodeModel.find_by_ip(request.environ['HTTP_HOST'])
        #Node without a blockchain is None
        if self_node is None:
            self_node = NodeModel(ip=request.environ['HTTP_HOST'])
            db.session.add(self_node)
            self_node.create_key_pair()
            #self_node.create_password()
            db.session.commit()

        self_node_db = NodeModel.find_by_ip(request.environ['HTTP_HOST'])
        new_node_url = 'http://' + request.environ['HTTP_HOST'] + '/'
        new_blockchain.register_node(node_url=new_node_url, node_public_key=self_node_db.node_public_key)
        response = {'message': "the blockchain '{}' was created".format(blockchain_name),
                    'node_public_key': self_node_db.node_public_key}
        return response, 200


class BlockchainNodes(Resource):

    #get_nodes
    def get(self, blockchain_name):
        blockchain = BlockchainModel.find_by_name(blockchain_name)
        if blockchain is None:
            return {"message": "This blockchain '{}' does not exist".format(blockchain_name)}, 400

        # node_original = blockchain.json()
        # node = blockchain_schema.dump(blockchain)
        # nodes = node['nodes']
        # response = {'nodes': nodes}
        response = blockchain_schema.dump(blockchain)["nodes"]
        return response, 200


    #register_nodes
    def post(self, blockchain_name):
        if BlockchainModel.find_by_name(blockchain_name) is None:
            return {"message": "This blockchain '{}' does not exist".format(blockchain_name)}, 400

        blockchain = select_blockchain(blockchain_name)
        error_nodes = []

        nodes = request.json['nodes'].replace(" ", "").split(',')


        if nodes is None:
            return "Error: Please supply a valid list of nodes", 400

        for node in nodes:
            request_json = {"existing_blockchain": "True"}
            response = requests.post(node + '/' + blockchain_name, json=request_json)
            # #The nodes availables to add a blockchain named like that
            if response.status_code == 200:
                node_public_key = response.json()['node_public_key']
                blockchain.register_node(node, node_public_key)
            else:
                error_nodes.append(node)

        for new_node in list(blockchain.nodes):
            if new_node == request.environ['HTTP_HOST']:
                pass
            else:
                for node_to_registered in list(blockchain.nodes):
                    node_register = 'http://' + node_to_registered
                    node_register_db = NodeModel.find_by_ip(node_to_registered)
                    json_payload = {
                        'nodes': node_register,
                        'node_public_key': node_register_db.node_public_key
                    }
                    requests.put('http://' + new_node + '/' + blockchain_name + '/nodes',
                                 json=json_payload)

        blockchain_db = BlockchainModel.find_by_name(blockchain_name)
        #nodes_db_origina = blockchain_db.json()['nodes']
        nodes_db = blockchain_db.nodes_in()
        response = {
            'message': 'New nodes have been added',
            'total_nodes': nodes_db,
            'error_nodes': error_nodes
        }
        return response, 201


    #nodes_update
    def put(self, blockchain_name):
        if BlockchainModel.find_by_name(blockchain_name) is None:
            return {"message": "This blockchain '{}' does not exist".format(blockchain_name)}, 400

        blockchain = select_blockchain(blockchain_name)
        values = request.json
        nodes = values['nodes'].replace(" ", "").split(',')
        node_pk = values['node_public_key']

        if nodes is None:
            return "Error: Please supply a valid list of nodes", 400

        for node in nodes:
            blockchain.register_node(node, node_pk)

        blockchain_db = BlockchainModel.find_by_name(blockchain_name)
        # nodes_db_origina = blockchain_db.json()['nodes']
        nodes_db = blockchain_db.nodes_in()

        blockchain = select_blockchain(blockchain_name)
        replaced = blockchain.resolve_conflicts(blockchain_name)

        response = {
            'message': 'New nodes have been added',
            'total_nodes': nodes_db,
        }

        return response, 201


class BlockchainRecords(Resource):

    #get_transactions - Get records from records pool not in the chain yet
    def get(self, blockchain_name):
        if BlockchainModel.find_by_name(blockchain_name) is None:
            return {"message": "This blockchain '{}' does not exist".format(blockchain_name)}, 400

        blockchain = select_blockchain(blockchain_name)

        # Get records from records pool
        # not in the chain yet
        records = blockchain.records

        response = {'records': records}
        return response, 200


    def post(self, blockchain_name):
        if BlockchainModel.find_by_name(blockchain_name) is None:
            return {"message": "This blockchain '{}' does not exist".format(blockchain_name)}, 400

        # record = record_schema.load(request.get_json())

        values = request.json
        blockchain = select_blockchain(blockchain_name)

        # record_result_2 = blockchain.submit_record(record.sender_address, record.record_data, record.signature)

        record_result = blockchain.submit_record(values['sender_address'], values['record_data'], values['signature'])
        if record_result == False:
            response = {'message': 'Invalid record!'}
            return response, 406
        else:
            response = {'message': 'record will be added to Block ' + str(record_result)}
            return response, 201

    #consensus
    def put(self, blockchain_name):
        if BlockchainModel.find_by_name(blockchain_name) is None:
            return {"message": "This blockchain '{}' does not exist".format(blockchain_name)}, 400

        blockchain = select_blockchain(blockchain_name)
        replaced = blockchain.resolve_conflicts(blockchain_name)
        chain = blockchain.chain
        global time_new_block
        time_new_block = time.time()
        # Si ya se ha producido el minado, ya se puede volver a hacer solicitud de bloque y no hace falta esperar X segundos
        global waiting
        #comentar esto para forzar a los 12 segundos de espera
        waiting = False

        blockchain_db = BlockchainModel.find_by_name(blockchain_name)

        if replaced:
            response = {
                'message': 'Our chain was replaced',
                'new_chain': [block_schema.dump(block) for block in blockchain_db.blocks.all()]
            }
        else:
            response = {
                'message': 'Our chain is authoritative',
                'chain': [block_schema.dump(block) for block in blockchain_db.blocks.all()]
            }
        return response, 200


class BlockchainChain(Resource):

    #full_chain
    def get(self, blockchain_name):
        if BlockchainModel.find_by_name(blockchain_name) is None:
            return {"message": "This blockchain '{}' does not exist".format(blockchain_name)}, 400

        blockchain = select_blockchain(blockchain_name)
        self_node = NodeModel.find_by_ip(request.environ['HTTP_HOST'])
        chain = blockchain.chain
        response = {
            'chain': blockchain.chain,
            'node_public_key': self_node.node_public_key,
            'length': len(blockchain.chain),
        }

        return response, 200

    #new_block_solicitude
    def post(self, blockchain_name):
        if BlockchainModel.find_by_name(blockchain_name) is None:
            return {"message": "This blockchain '{}' does not exist".format(blockchain_name)}, 400
        blockchain = select_blockchain(blockchain_name)
        if len(blockchain.records) == 0:
            return {'message': 'there is not record available'}, 400
        min_accepted = len(blockchain.nodes) * (2 / 3)

        ack_counter = 1  # empieza por 1 porque ya cuento con mi propio ACK
        self_node_db = NodeModel.find_by_ip(request.environ['HTTP_HOST'])
        # payload = 'new_block_solicitude'

        for node in list(blockchain.nodes):
            if node == request.environ['HTTP_HOST']:
                pass
            else:
                request_json = {'node_ip': request.environ['HTTP_HOST'],
                                'node_public_key': self_node_db.node_public_key}
                node_token_tx = NodeModel.find_by_ip(node).node_token
                response = requests.put('http://' + node + "/" + str(blockchain_name) + '/chain',
                                        json=request_json, headers={'Authorization': 'Bearer ' + node_token_tx})
                if response.status_code == 200:
                    ack_counter += 1
                if response.status_code == 409:
                    pass
                if response.status_code == 401:
                    refresh_login(request.environ['HTTP_HOST'], node)
                    request_json = {'node_ip': request.environ['HTTP_HOST'],
                                    'node_public_key': self_node_db.node_public_key}
                    node_token_tx = NodeModel.find_by_ip(node).node_token
                    response = requests.put('http://' + node + "/" + str(blockchain_name) + '/chain',
                                            json=request_json, headers={'Authorization': 'Bearer ' + node_token_tx})

                    if response.status_code == 200:
                        ack_counter += 1
                    if response.status_code == 409:
                        pass
                    if response.status_code == 401:
                        return {'error': 'token expired'}, 401

        if ack_counter >= min_accepted:
            result = mine(blockchain_name)
            waiting_bool = waiting
            response = {
                'result': result,
                'message': 'ACK, block added to the chain. '
            }
            return response, 200
        else:
            response = {
                "message": "NOT ACK OF '{}' nodes. You can not add the block yet.".format(MIN_ACCEPT)
            }
            return response, 403

    #new_block_admission
    @jwt_required
    def put(self, blockchain_name):
        values = request.json

        if NodeModel.find_by_ip(values['node_ip']) is None:
            return "This node does not exist in that blockchain", 400
        if NodeModel.find_by_ip(values['node_ip']).node_public_key != values['node_public_key']:
            return "Node corrupted", 400

        result = new_block_control()
        resting_time = result['new_time']
        if result['new_block_result'] is True:
            global waiting
            waiting = True
            response = {
                'message': 'ACK, you can add the block and the new_time is {}'.format(resting_time),
                'new_time': resting_time
            }
            return response, 200
        else:
            response = {
                'message': 'NACK, you cannot add the block and the new_time is {}'.format(resting_time),
                'new_time': resting_time
            }
            return response, 409

class TestApi(Resource):

    def get(self):
        #aseguro que el nodo X puede comunicarse correctamente con el nodo 2 porque tiene el token
        # node = '127.0.0.1:5002'
        request_json = {
            'message': 'prueba'
        }
        json = request.get_json()
        node_data = node_schema.load(json)
        try:
            node_token_tx = NodeModel.find_by_ip(node_data.ip).node_token
        except:
            return {'message': 'unknown node'}, 400

        response = requests.post('http://' + node_data.ip + '/testapi',
                                json=request_json, headers={'Authorization': 'Bearer ' + node_token_tx})
        if response.status_code == 200:
            response = {'message': 'JWT ok'}
            return response, 200

        if response.status_code == 401:
            response = {'message': 'token has expired'}
            return response, 401

        if response.status_code == 422:
            response = {'message': 'bad JWT'}
            return response, 422

        response = {'message': 'bad'}
        return response, 403

    @classmethod
    @jwt_required
    def post(self):
        return {'message': 'autorizado'}, 200


def select_blockchain(blockchain_name):
    for k in list_blockchains:
        if blockchain_name == k.blockchain_name:
            blockchain = k
            return blockchain
        else:
            pass
    return ("invalid blockchain")

def new_block_control():
    current_date = time.time()
    new_time = current_date - time_new_block
    waiting_bool = waiting
    if new_time > 12 or waiting_bool == False:
    # if new_time > 12:
        new_block_result = True #si supera los 12 segundos vuelve a dejar que haya bloque
    else:
        new_block_result = False #si no está libre, entonces niega la adhesion
    response = {
                "new_block_result": new_block_result,
                "new_time": new_time,
                        }
    return response

def mine(blockchain_name):
    blockchain = select_blockchain(blockchain_name)
    blockchain_db = BlockchainModel.find_by_name(blockchain_name)
    if len(blockchain.records) == 0:
        return {'message': 'there is not record available'}, 400

    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    # We must receive a reward for finding the proof.
    # solo funciona quitarlo si establecemos MINING_DIFFICULTY = 0, sino =2 (valor original)
    # blockchain.submit_record(sender_address=MINING_SENDER, record_data=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    new_records = blockchain.records
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    new_block = BlockModel(block_num=block['block_number'],
                           previous_hash=block['previous_hash'],
                           time_stamp=block['time_stamp'],
                           id_blockchain=blockchain_db.id_blockchain,
                           nonce=block['nonce'])
    new_block.save_to_db()

    for record in new_records:
        new_record = RecordModel(record_data=record['record_data'],
                                 id_user=UserModel.find_by_public_key(record['sender_address']).id_user,
                                 id_block=new_block.id_block)
        new_record.save_to_db()

    for node in blockchain.nodes:
        requests.put('http://' + node + "/" + str(blockchain_name) + '/records')


    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'records': block['records'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return response

def refresh_login(self_node_ip, node):
    self_node = NodeModel.find_by_ip(self_node_ip)
    login_credentials = {
        'ip': self_node.ip
    }
    #POST in order to obtain the challenge
    result = requests.post('http://' + node + '/login', json=login_credentials)
    challenge_response = result.json()['challenge']
    signature = self_node.sign_response(challenge_response)
    login_response = {
        'ip': self_node.ip,
        'response': challenge_response,
        'signature': signature
    }
    #POST in order to obtain the tokens
    save_tokens = requests.post('http://' + node + '/login', json=login_response)
    if save_tokens.status_code == 200:
        node_access = NodeModel.find_by_ip(node)
        # almacenamos el token asociado a ese nodo
        #if safe_str_cmp(save_tokens.json()['node_public_key'], node_access.node_public_key):
        node_access.node_token = save_tokens.json()['access_token']
        node_access.node_refresh_token = save_tokens.json()['refresh_token']
        node_access.save_to_db()

        return {"message": "User logged successfully."}, 200
    # return {"message": "Not found."}, 404

