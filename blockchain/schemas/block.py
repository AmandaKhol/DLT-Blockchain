"""
title           : block.py
description     : Schema of the block
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

from ma import ma
from blockchain.models.block import BlockModel
from blockchain.models.blockchain import BlockchainModel
from blockchain.models.record import RecordModel
from blockchain.schemas.record import RecordSchema

class BlockSchema(ma.SQLAlchemyAutoSchema):
    records = ma.Nested(RecordSchema, many=True)
    class Meta:
        model = BlockModel
        load_only = ("blockchain",)
        dump_only = ("id",)
        load_instance = True
        include_fk = True