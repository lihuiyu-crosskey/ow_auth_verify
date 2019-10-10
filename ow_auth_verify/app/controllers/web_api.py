#-*- coding: UTF-8 -*-
from app.services import web_ser
from flask import jsonify, request, redirect, make_response,Flask
from app import logged,beforeLogin
from ..Messages.mess_handler import Message
from datetime import datetime
from flask import current_app





@beforeLogin.route('/access_token/get', methods=['POST'],endpoint='用refresh_token换取access_token')
def refresh_token():
    try:
        req=request.get_json()
        return web_ser.refresh_token(req['refresh_token'])
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400,"参数错误","")
