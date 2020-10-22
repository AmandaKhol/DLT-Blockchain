"""
title           : record.py
description     : Schema of the record
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

from ma import ma
from blockchain.models.record import RecordModel
from blockchain.models.user import UserModel
from blockchain.models.block import BlockModel


class RecordSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = RecordModel
        load_only = ("user", "block")
        dump_only = ("id",)
        load_instance = True
        include_fk = True