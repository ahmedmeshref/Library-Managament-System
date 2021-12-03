import os


class Config:
    DEBUG = True
    CSRF_ENABLED = True
    SECRET_KEY = os.urandom(32)
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:250787388219@localhost:5432/' + 'libSys'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

