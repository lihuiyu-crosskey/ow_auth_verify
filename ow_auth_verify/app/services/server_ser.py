# -*- coding: UTF-8 -*-
from ..Messages.mess_handler import Message
import base64
import hashlib
import json
import time
import ast
from flask import current_app
import string, random
import manage
import threading


#权限验证
def verify_power(token, url, uid):
    try:
        manage.cur.reconnect()
        #token解析
        tokens = str(token)
        token = str(token)
        token = token.split('.')
        header = token[0]
        payload = token[1]
        header_c = decode_token_bytes(header)
        header_c = ast.literal_eval(header_c)
        header_c = json.dumps(header_c)
        data = json.loads(header_c.decode("utf8"))
        type = data['token_type']
        if str(type) != "access":
            return Message.json_mess(4, 'token类型错误', '')
        payload_d = decode_token_bytes(payload)
        data = json.loads(payload_d.decode("utf8"))
        #判断调用此接口的user_id是否与token里的user_id相同
        user_id = data.get('user_id')
        platform_type = data['platform_type']
        access_token = tokens
        if platform_type == 'mobile':
            orgin_access_token = manage.red.get('mobile_refresh_token_' + str(user_id))
        else:
            orgin_access_token = manage.red.get('web_refresh_token_' + str(user_id))
        if orgin_access_token:
            if orgin_access_token == access_token:
                pass
            else:
                return Message.json_mess(20, 'access_token签名验证错误', '')
        else:
            return Message.json_mess(1, 'token过期', '')

        if uid != '':
            if str(uid) != str(user_id):
                return Message.json_mess(5, 'uid与token不匹配', '')

        if int(user_id)  > 0:
            key="user_"+str(user_id)
            #先取Redis里的用户信息，如果Redis里没有则从数据库取
            a = manage.red.get("user_info_"+str(user_id))
            if a:
                a = json.loads(a)
                if int(a['status']) ==1 :
                    return Message.json_mess(14,"账户已经被封","")
                if int(a['status']) ==2 :
                    return Message.json_mess(15,"账户不存在","")
                role_id = a['role_id']
            else:
                sql="select * from tab_user where id=%s and status!=2 limit 1"
                b=manage.cur.get(sql,user_id)
                if b:
                    if int(b['status'])==1:
                        return Message.json_mess(14, "账户已经被封", "")
                    role_id = b['role_id']
                else:
                    return Message.json_mess(15,"账户不存在","")
        else:
            return Message.json_mess(15, "账户不存在", "")
        #超管的role_id为0，这边判断是否是超管
        if int(role_id) == 0:
            return Message.json_mess(0, '验证成功', '')
        #从Redis里取出此角色的所有权限，判断是否存在调用该接口的权限
        # power=red_user_info.smembers("role_"+str(role_id))
        # if power:
        #     for i in power:
        #         i=ast.literal_eval(i)
        #         if int(i['power_type'])==1:
        #             if str(url) == str(i['power_url']):
        #                 return Message.json_mess(0, '验证成功', '')
        sql="""SELECT a.role_id,d.power_code FROM tab_role_power_group a
INNER JOIN tab_power_group b on a.power_group_id=b.id
INNER JOIN tab_power_group_power c on b.id=c.power_group_id
INNER JOIN tab_power d on c.power_id=d.id
WHERE a.role_id=%s AND d.power_code=%s limit 1"""
        check_power=manage.cur.get(sql,role_id,url)
        if check_power:
            return Message.json_mess(0, '验证成功', '')
        else:
            return Message.json_mess(13, '无此权限', '')


    except Exception as e:
        # print e
        current_app.logger.error(str(e))
        return Message.json_mess(16, '权限验证失败',"")
    finally:
        manage.cur.close()



def header_check(head):
    try:
        funkiSystem = head['OperationPlatform']
        check_sys=['iOS','Android','Web','Backstage']
        if funkiSystem in check_sys:
            if funkiSystem != 'serverFunki':
                softwareName = head['softwareName']
                imei = head['imei']
                session = head['session']
                system = head['system']
                deviceName = head['deviceName']
                deviceType = head['deviceType']
                ip = head['ip']
                geo = head['geo']
                isBreak = head['isBreak']
                version = head['funkiVersion']
                timestamp = time.time()
                res = {'funkiSystem': funkiSystem, 'softwareName': softwareName, 'imei': imei, 'session': session,
                       'system': system, 'deviceName': deviceName, 'deviceType': deviceType, 'ip': ip, 'geo': geo,
                       'isBreak': isBreak,'funkiVersion':version, 'timestamp': timestamp}
            else:
                ip = head['ip']
                timestamp = time.time()
                res={'funkiSystem': funkiSystem,'timestamp': timestamp,'ip':ip}

            # Message.mq_send(config.mq_header['routing_key'], res, config.mq_header['user'],
            #                 config.mq_header['pwd'],
            #                 config.mq_header['url'], config.mq_header['exchange'], config.mq_header['exchange_type'])
            return True
        else:
            return False
    except Exception as e:
        current_app.logger.error(str(e))
        return False


def save_my_apis(apis):
    my_thread=threading.Thread(target=save_api, args=(apis,))
    my_thread.start()
    return Message.json_mess(0,'添加成功','')


def save_api(apis):
    try:
        manage.cur.reconnect()
        for api in apis:
            power_code=api['power_code']
            power_name=api['power_name']
            power_mark=api['power_mark']
            sql='select * from tab_power where power_code=%s limit 1'
            check=manage.cur.get(sql,power_code)
            print(check)
            if check:
                pass
            else:
                sql="insert into tab_power(power_name,power_code,type,power_mark) values (%s,%s,1,%s)"
                check=manage.cur.execute(sql,power_name,power_code,power_mark)
                print(check)

        return 0
    except Exception as e:
        current_app.logger.error(str(e))
        return 1
    finally:
        manage.cur.close()






def get_token_body(token):
    token = str(token)
    token = token.split('.')
    payload = token[1]
    payload_d = decode_token_bytes(payload)
    data = json.loads(payload_d.decode("utf8"))
    return data



# 加密
def _get_signature(value):
    """Calculate the HMAC signature for the given value."""
    mySha = hashlib.sha256()
    mySha.update(value)
    # print mySha.hexdigest()
    return mySha.hexdigest()

# 下面两个函数将base64编码和解码单独封装
def encode_token_bytes(data):
    return base64.urlsafe_b64encode(data)

def decode_token_bytes(data):
    return base64.urlsafe_b64decode(data)




# def random_str(randomlength):
#     str = ''
#     chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
#     length = len(chars) - 1
#     random = Random()
#     for i in range(randomlength):
#         str+=chars[random.randint(0, length)]
#
#     check=red_username_set.sismember("username",str)
#     if check:
#         random_str(randomlength)
#     else:
#         red_username_set.sadd("username",str)
#     return str


fontPath = "/usr/share/fonts/truetype/ttf-devanagari-fonts/"

# 获得随机四个字母
def getRandomChar():
    return [random.choice(string.letters) for _ in range(4)]



