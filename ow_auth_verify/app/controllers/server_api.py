#-*- coding: UTF-8 -*-
from app.services import web_ser,server_ser
from flask import request
from app import server
from ..Messages.mess_handler import Message
from flask import current_app

@server.route('/power/verify', methods=['POST'],endpoint='根据access_token验证权限')
def power_verify():
    try:
        req=request.get_json()
        header=req["header"]
        token=header['token']
        url=req['url']
        uid=req['uid']
        data = server_ser.verify_power(token,url,uid)
        return data
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")

@server.route('/apis/save', methods=['POST'],endpoint='添加所有服务的接口权限')
def save_my_apis():
    try:
        req=request.get_json()
        data = server_ser.save_my_apis(req['apis'])
        return data
    except Exception as e:
        current_app.logger.error(e)
        return Message.json_mess(400, "参数错误", "")


