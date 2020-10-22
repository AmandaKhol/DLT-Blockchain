"""
title           : node.py
description     : Schema of the node
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

from ma import ma
from blockchain.models.node import NodeModel
# from blockchain.models.blockchain import BlockchainModel
# from blockchain.schemas.blockchain import BlockchainSchema


class NodeSchema(ma.SQLAlchemyAutoSchema):
    #blockchains = ma.Nested(BlockchainSchema, many=True)
    class Meta:
        model = NodeModel
        load_only = ("node_public_key",)
        dump_only = ("id", "challenge_created")
        load_instance = True
        include_fk = True
