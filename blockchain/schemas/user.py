"""
title           : user.py
description     : Schema of the user
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

from ma import ma
from blockchain.models.user import UserModel
from blockchain.models.record import RecordModel
from blockchain.schemas.record import RecordSchema


class UserSchema(ma.SQLAlchemyAutoSchema):
    records = ma.Nested(RecordSchema, many=True)
    class Meta:
        model = UserModel
        dump_only = ("id",)
        load_instance = True
        include_fk = True