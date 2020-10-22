"""
title           : blockchain.py
description     : Schema of the blockchain
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""


from ma import ma

from marshmallow import fields
from blockchain.models.blockchain import BlockchainModel
from blockchain.models.block import BlockModel
from blockchain.models.node import NodeModel
from blockchain.schemas.block import BlockSchema
from blockchain.schemas.node import NodeSchema

class BlockchainSchema(ma.SQLAlchemyAutoSchema):
    blocks = ma.Nested(BlockSchema, many=True)
    nodesin = ma.Nested(NodeSchema(only=("ip", )), data_key="nodes", many=True)
    length = fields.Method("length_calc")
    class Meta:
        model = BlockchainModel
        dump_only = ("id",)
        load_instance = True
        include_fk = True

    def length_calc(self, obj):
        return len(obj.blocks.all())




