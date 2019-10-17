# -*- coding:utf-8 -*-
from flask import Blueprint

logged = Blueprint('logged', __name__,url_prefix='/auth_verify')
beforeLogin=Blueprint('beforeLogin',__name__,url_prefix='/auth_verify')
server=Blueprint('server', __name__,url_prefix='/auth_verify/server')

from app.controllers import web_api,server_api
from app.Messages import mess_handler