# -*- coding:utf-8 -*-
"""
Module Description:
Date: 2019-6-28
Author: lihuiyu
"""
import os

basedir = os.path.abspath(os.path.dirname(__file__))
check=os.getenv('FLASK_CONFIG')
# check='test'
if check=='local':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5555
    db_set={'name':'root','password':'ZTkj2018!','host':'192.168.1.203','port':'3306','db':'auth_test'}
    redis_set={'host':'192.168.1.203','port':'6379','password':'admin123!','db':'0'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379','password':'admin123!', 'db': '1'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379','password':'admin123!', 'db': '2'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379','password':'admin123!', 'db': '3'}
elif check=='online':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5555
    db_set = {'name': 'root', 'password': 'Wushuang2009!', 'host': '149.129.61.116', 'port': '3306', 'db': 'auth_online'}
    redis_set = {'host': '149.129.61.116', 'port': '6179', 'password': 'admin123!', 'db': '0'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '1'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '2'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379', 'password': 'admin123!', 'db': '3'}
elif check=='test':
    access_token_expire = 3600
    refresh_token_expire = 2592000
    port=5555
    db_set = {'name': 'root', 'password': 'ZTkj2018!', 'host': '192.168.1.203', 'port': '3306', 'db': 'auth_test'}
    redis_set = {'host': '192.168.1.203', 'port': '6379','password':'admin123!', 'db': '0'}
    redis_access_token = {'host': '192.168.1.203', 'port': '6379', 'password':'admin123!','db': '1'}
    redis_refresh_token = {'host': '192.168.1.203', 'port': '6379','password':'admin123!', 'db': '2'}
    redis_user_info = {'host': '192.168.1.203', 'port': '6379','password':'admin123!', 'db': '3'}



class Config:
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
        DEBUG = False
        SQLALCHEMY_ECHO=True
        SQLALCHEMY_POOL_SIZE=10
        SQLALCHEMY_POOL_RECYCLE = 5
        SQLALCHEMY_DATABASE_URI = "mysql://%s:%s@%s:%s/%s"%(db_set['name'],db_set['password'],db_set['host'],db_set['port'],db_set['db'])

    # MAIL_SERVER = 'email-smtp.us-west-2.amazonaws.com'
    # MAIL_PROT = 587
    # MAIL_USE_TLS = True
    # MAIL_USE_SSL = False
    # MAIL_USERNAME = "AKIAIXEVFGVWK7ILOO6A"
    # MAIL_PASSWORD = "AjAtYAjw8J5IgP8c4zckZQNDsCMhvW6gw0WkX1KjhQGV"
    # MAIL_DEBUG = True







config = {
    'default': DevelopmentConfig,
    'online':DevelopmentConfig,
    'test':DevelopmentConfig
}


