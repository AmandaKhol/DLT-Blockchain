"""
title           : block.py
description     : Model of the block
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""


from db import db

class BlockModel(db.Model):
    __tablename__ = 'blocks'

    __table_args__ = {'extend_existing': True}

    id_block = db.Column(db.Integer, primary_key=True)
    block_num = db.Column(db.Integer, nullable=False)
    previous_hash = db.Column(db.String, nullable=False)
    nonce = db.Column(db.String, nullable=False)
    time_stamp = db.Column(db.Float, nullable=False)

    id_blockchain = db.Column(db.String, db.ForeignKey('blockchains.id_blockchain'), nullable=False)
    blockchain = db.relationship('BlockchainModel')

    records = db.relationship('RecordModel', lazy='dynamic')

    # def __init__(self, block_num, previous_hash, time_stamp, id_blockchain, nonce):
    #     self.block_num = block_num
    #     self.previous_hash = previous_hash
    #     self.time_stamp = time_stamp
    #     self.id_blockchain = id_blockchain
    #     self.nonce = nonce


    # def json(self):
    #     return {'block_num': self.block_num,
    #             'previous_hash': self.previous_hash,
    #             'time_stamp': self.time_stamp,
    #             'id_blockchain': self.id_blockchain,
    #             'nonce': self.nonce,
    #             'records': [record.json() for record in self.records.all()]
    #             }


    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id_block=_id).first()

    @classmethod
    def find_by_block_num(cls, _block_num):
        return cls.query.filter_by(block_num=_block_num).first()

    @classmethod
    def find_last_block(cls, id_blockchain):
        id_bc = id_blockchain
        value = cls.query.filter_by(id_blockchain=id_bc).order_by(cls.block_num.desc()).first()
        return value

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()