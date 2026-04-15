import requests
import os
import psutil
import sys
import jwt
import pickle
import json
import binascii
import time
import urllib3
import xKEys
import base64
import re
import socket
import threading
import random
from datetime import datetime
from protobuf_decoder.protobuf_decoder import Parser
from black9 import *          # يجب أن يحتوي على EnC_AEs, DeCode_PackEt, EnC_Uid, xMsGFixinG
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ====================== دوال توليد التوكن (من الكود الأول) ======================
def Ua():
    TmP = "GarenaMSDK/4.0.13 ({}; {}; {};)"
    return TmP.format(random.choice(["iPhone 13 Pro", "iPhone 14", "iPhone XR", "Galaxy S22", "Note 20", "OnePlus 9", "Mi 11"]),
                     random.choice(["iOS 17", "iOS 18", "Android 13", "Android 14"]),
                     random.choice(["en-SG", "en-US", "fr-FR", "id-ID", "th-TH", "vi-VN"]))

def xGeT(u, p):
    """توليد التوكن من Garena باستخدام UID وكلمة المرور"""
    print(f"جاري توليد التوكن لـ UID: {u}")
    try:
        r = requests.Session().post(
            "https://100067.connect.garena.com/oauth/guest/token/grant",
            headers={
                "Host": "100067.connect.garena.com",
                "User-Agent": Ua(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "close"
            },
            data={
                "uid": u,
                "password": p,
                "response_type": "token",
                "client_type": "2",
                "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                "client_id": "100067"
            },
            verify=False
        )
        if r.status_code == 200:
            T = r.json()
            print("تم الحصول على التوكن بنجاح من Garena")
            a, o = T["access_token"], T["open_id"]
            jwt_token = xJwT(a, o)
            return jwt_token
        else:
            print(f"خطأ في الاستجابة من Garena: {r.status_code}")
            return None
    except Exception as e:
        print(f"حدث خطأ في xGeT: {str(e)}")
        return None

def xJwT(access_token, open_id):
    """
    توليد JWT باستخدام access_token و open_id (محدث لـ OB53 وسيرفر ggpolarbear.com)
    """
    try:
        # قالب payload الخاص بـ OB53 (تم استخراجه من البيانات المرفقة)
        template_hex = (
            "1a13323032352d31312d32362030313a35313a3238220966726565206669726528013a07312e3132332e3142"
            "32416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e31"
            "3134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d005720332"
            "34307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030"
            "207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b"
            "476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a201"
            "0e3137362e32382e3133392e313835aa01026172b2012034333036323435373933646538366461343235613532"
            "63616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014063"
            "363961653230386661643732373338623637346232383437623530613361316466613235643161313966616537"
            "343566633736616334613065343134633934f00101ca020c4d544e2f537061636574656cd2020457494649ca03"
            "203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e8039a8002f003"
            "af13f80384078004a78f028804b5ee029004a78f029804b5ee02b00404c80401d2043d2f646174612f6170702f"
            "636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c"
            "69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c"
            "2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c"
            "2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b2"
            "05094f70656e474c455332b805ff01c00504e005be7eea05093372645f7061727479f205704b71734854385739"
            "3347646347335a6f7a454e6646775648746d377171316552554e6149444e67526f626f7a4942744c4f69594363"
            "3459367a767670634943787a514632734f453463627974774c7334785a62526e70524d706d5752514b6d654f35"
            "766373386e51594268777148374bf805e7e4068806019006019a060134a2060134b2062213521146500e590349"
            "510e460900115843395f005b510f685b560a6107576d0f0366"
        )
        dT = bytes.fromhex(template_hex)
        
        # تحديث التاريخ والوقت الحالي
        now_str = str(datetime.now())[:-7]
        dT = dT.replace(b'2025-11-26 01:51:28', now_str.encode())
        
        # تحديث open_id
        old_open_id = b'4306245793de86da425a52caadf21eed'
        dT = dT.replace(old_open_id, open_id.encode())
        
        # تحديث access_token
        old_token = b'c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94'
        dT = dT.replace(old_token, access_token.encode())
        
        encrypted_hex = EnC_AEs(dT.hex())
        PyL = bytes.fromhex(encrypted_hex)
        
        r = requests.Session().post(
            "https://loginbp.ggpolarbear.com/MajorLogin",
            headers={
                "Expect": "100-continue",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB53",
                "Authorization": "Bearer ",
                "Host": "loginbp.ggpolarbear.com"
            },
            data=PyL,
            verify=False
        )
        
        if r.status_code == 200:
            response_data = json.loads(DeCode_PackEt(binascii.hexlify(r.content).decode('utf-8')))
            jwt_token = response_data['8']['data']
            print("تم توليد JWT بنجاح")
            return jwt_token
        else:
            print(f"خطأ في MajorLogin: {r.status_code}")
            return None
    except Exception as e:
        print(f"حدث خطأ في xJwT: {str(e)}")
        return None

def generate_jwt_from_data(open_id, access_token):
    return xJwT(access_token, open_id)

# ====================== دوال الكود الثاني (spam, info, delete, etc) ======================
def ToK():
    while True:
        try:
            r = requests.get('https://tokens-asfufvfshnfkhvbb.francecentral-01.azurewebsites.net/ReQuesT?&type=ToKens')
            t = r.text
            i = t.find("ToKens : [")
            if i != -1:
                j = t.find("]", i)
                L = [x.strip(" '\"") for x in t[i+11:j].split(',') if x.strip()]
                if L:
                    with open("token.txt", "w") as f:
                        f.write(random.choice(L))
        except: pass
        time.sleep(5 * 60 * 60)

# تشغيل خلفية لجلب التوكنات
Thread(target=ToK, daemon=True).start()

def GeTToK():
    with open("token.txt") as f:
        return f.read().strip()

def Likes(id):
    try:
        text = requests.get(f"https://tokens-asfufvfshnfkhvbb.francecentral-01.azurewebsites.net/ReQuesT?id={id}&type=likes").text
        get = lambda p: re.search(p, text)
        name, lvl, exp, lb, la, lg = (get(r).group(1) if get(r) else None for r in 
            [r"PLayer NamE\s*:\s*(.+)", r"PLayer SerVer\s*:\s*(.+)", r"Exp\s*:\s*(\d+)", 
             r"LiKes BeFore\s*:\s*(\d+)", r"LiKes After\s*:\s*(\d+)", r"LiKes GiVen\s*:\s*(\d+)"])
        return name, f"{lvl}" if lvl else None, int(lb) if lb else None, int(la) if la else None, int(lg) if lg else None
    except:
        return None, None, None, None, None

def Requests_SPam(id):
    Api = requests.get(f'https://tokens-asfufvfshnfkhvbb.francecentral-01.azurewebsites.net/ReQuesT?id={id}&type=spam')
    if Api.status_code in [200, 201] and '[SuccessFuLy] -> SenDinG Spam ReQuesTs !' in Api.text:
        return True
    else:
        return False

def GeT_Name(uid, Token):
    time.sleep(1)
    data = bytes.fromhex(EnC_AEs(f"08{EnC_Uid(uid, Tp='Uid')}1007"))
    url = "https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow"
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB52',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {Token}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    response = requests.post(url, headers=headers, data=data, verify=False)
    if response.status_code in [200, 201]:
        packet = binascii.hexlify(response.content).decode('utf-8')
        BesTo_data = json.loads(DeCode_PackEt(packet))
        try:
            a1 = BesTo_data["1"]["data"]["3"]["data"]
            return a1
        except:
            return ''
    else:
        return ''

def GeT_PLayer_InFo(uid, Token):
    data = bytes.fromhex(EnC_AEs(f"08{EnC_Uid(uid, Tp='Uid')}1007"))
    url = "https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow"
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB52',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {Token}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    response = requests.post(url, headers=headers, data=data, verify=False)
    if response.status_code in [200, 201]:
        packet = binascii.hexlify(response.content).decode('utf-8')
        BesTo_data = json.loads(DeCode_PackEt(packet))
        NoCLan = False
        try:
            a1 = str(BesTo_data["1"]["data"]["1"]["data"])
            a2 = BesTo_data["1"]["data"]["21"]["data"]
            a3 = BesTo_data["1"]["data"]["3"]["data"]
            player_server = BesTo_data["1"]["data"]["5"]["data"]
            player_bio = BesTo_data["9"]["data"]["9"]["data"]
            player_level = BesTo_data["1"]["data"]["6"]["data"]
            account_date = datetime.fromtimestamp(BesTo_data["1"]["data"]["44"]["data"]).strftime("%I:%M %p - %d/%m/%y")
            last_login = datetime.fromtimestamp(BesTo_data["1"]["data"]["24"]["data"]).strftime("%I:%M %p - %d/%m/%y")
            try:
                clan_id = BesTo_data["6"]["data"]["1"]["data"]
                clan_name = BesTo_data["6"]["data"]["2"]["data"]
                clan_leader = BesTo_data["6"]["data"]["3"]["data"]
                clan_level = BesTo_data["6"]["data"]["4"]["data"]
                clan_members_num = BesTo_data["6"]["data"]["6"]["data"]
                clan_leader_name = BesTo_data["7"]["data"]["3"]["data"]
            except:
                NoCLan = True
            if NoCLan:
                a = f'''
[FFFF00][1] - ProFile InFo :
[ffffff]	
 Name : {a3}
 Uid : {xMsGFixinG(a1)}
 Likes : {xMsGFixinG(a2)}
 LeveL : {player_level}
 Server : {player_server}
 Bio : {player_bio}
 Creating : {account_date}
 LasT LoGin : {last_login}
[90EE90]Dev : Neuf-t Team\n'''
                a = a.replace('[i]','')
                return a
            else:
                a = f'''
[b][c][90EE90] [SuccessFully] - Get PLayer s'InFo !
[FFFF00][1] - ProFile InFo :
[ffffff]	
 Name : {a3}
 Uid : {xMsGFixinG(a1)}
 Likes : {xMsGFixinG(a2)}
 LeveL : {player_level}
 Server : {player_server}
 Bio : {player_bio}
 Creating : {account_date}
 LasT LoGin : {last_login}
[b][c][FFFF00][2] - Guild InFo :
[ffffff]
 Guild Name : {clan_name}
 Guild Uid : {xMsGFixinG(clan_id)}
 Guild LeveL : {clan_level}
 Guild Members : {clan_members_num}
 Leader s'Uid : {xMsGFixinG(clan_leader)}
 Leader s'Name : {clan_leader_name}\n'''
                a = a.replace('[i]','')
                return a
        except Exception as e:
            return f'\n[b][c][FFD700]FaiLEd GeTinG PLayer InFo !\n'
    else:
        return f'\n[b][c][FFD700]FaiLEd GeTinG PLayer InFo !\n'

def DeLet_Uid(id, Tok):
    print(f' Done FuckinG > {id} ')
    url = 'https://clientbp.common.ggbluefox.com/RemoveFriend'
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB52',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {Tok}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    data = bytes.fromhex(EnC_AEs(f"08a7c4839f1e10{EnC_Uid(id, Tp='Uid')}"))
    ResPonse = requests.post(url, headers=headers, data=data, verify=False)
    if ResPonse.status_code == 400 and 'BR_FRIEND_NOT_SAME_REGION' in ResPonse.text:
        return f'[b][c]Id : {xMsGFixinG(id)} Not In Same Region !'
    elif ResPonse.status_code == 200:
        return f'[b][c]Good Response Done Delete Id : {xMsGFixinG(id)} !'
    else:
        return f'[b][c]Erorr !'

def ChEck_The_Uid(id):
    try:
        with open('uids.json', 'r') as f:
            data = json.load(f)
            user_data = data.get(str(id))
            if not user_data:
                return False
            status = user_data.get('status')
            expire = user_data.get('expire')
            if not expire:
                return (status, "No expire date")
            now = datetime.now()
            expire_date = datetime.fromtimestamp(expire)
            remaining_time = expire_date - now
            if remaining_time.total_seconds() <= 0:
                return (status, "Expired")
            days = remaining_time.days
            seconds = remaining_time.seconds
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            seconds = seconds % 60
            formatted_time = f"{days} Day - {hours} Hour - {minutes} Min - {seconds} Sec"
            return (status, formatted_time)
    except Exception as e:
        print(f"Error reading JSON: {e}")
        return False

# ====================== مثال للاستخدام ======================
if __name__ == "__main__":
    # مثال: استخدام التوكن المستخرج من السيرفر
    token = GeTToK()
    print(f"Current token: {token}")
    
    # مثال: جلب معلومات لاعب باستخدام UID معين
    uid_example = "1234567890"
    info = GeT_PLayer_InFo(uid_example, token)
    print(info)
    
    # مثال: حذف صديق
    # result = DeLet_Uid(uid_example, token)
    # print(result)