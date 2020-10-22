"""
title           : user.py
description     : Model of the user
author          : Amanda Garcia-Garcia
version         : 0
python_version  : 3.6.1

"""

from db import db

class UserModel(db.Model):
    __tablename__ = 'users'

    __table_args__ = {'extend_existing': True}

    id_user = db.Column(db.Integer, primary_key=True)
    public_key = db.Column(db.String(80), nullable=False)

    #Quien coje datos de el
    records = db.relationship('RecordModel', lazy='dynamic')


    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id_user=_id).first()


    @classmethod
    def find_by_public_key(cls, public_key):
        return cls.query.filter_by(public_key=public_key).first()


    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


