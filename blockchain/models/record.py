"""
title           : record.py
description     : Model of the record
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

from db import db

class RecordModel(db.Model):
    __tablename__ = 'records'

    id_record = db.Column(db.Integer, primary_key=True)
    record_data = db.Column(db.String, nullable=False)

    id_user = db.Column(db.String, db.ForeignKey('users.id_user'), nullable=False)
    user = db.relationship('UserModel')

    id_block = db.Column(db.Integer, db.ForeignKey('blocks.id_block'), nullable=False)
    block = db.relationship('BlockModel')


    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id_record=_id).first()


    def save_to_db(self):
        db.session.add(self)
        db.session.commit()




