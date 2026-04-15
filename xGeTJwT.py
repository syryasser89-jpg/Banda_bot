import requests
import time
import binascii
import json
import urllib3
import random
from datetime import datetime
from Black import EnC_AEs, DeCode_PackEt   # تأكد من وجود هاتين الدالتين في ملف Black.py

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    توليد JWT باستخدام access_token و open_id
    تم التعديل لدعم OB53 وسيرفر ggpolarbear.com
    """
    try:
        # القالب الثابت (تم تحديثه ليتوافق مع OB53 بناءً على البيانات المرفقة)
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
        
        # تحديث التاريخ والوقت الحالي (بصيغة YYYY-MM-DD HH:MM:SS)
        now_str = str(datetime.now())[:-7]  # تزيل أجزاء الثانية
        dT = dT.replace(b'2025-11-26 01:51:28', now_str.encode())
        
        # تحديث open_id (الموجود في القالب عند offset معين)
        # نبحث عن الـ open_id القديم في القالب ونستبدله
        old_open_id = b'4306245793de86da425a52caadf21eed'
        dT = dT.replace(old_open_id, open_id.encode())
        
        # تحديث access_token
        old_token = b'c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94'
        dT = dT.replace(old_token, access_token.encode())
        
        # تشفير البيانات باستخدام AES (الدالة من Black.py)
        encrypted_hex = EnC_AEs(dT.hex())
        PyL = bytes.fromhex(encrypted_hex)
        
        # إرسال الطلب إلى سيرفر OB53 الجديد
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
            jwt = response_data['8']['data']
            print("تم توليد JWT بنجاح")
            return jwt
        else:
            print(f"خطأ في MajorLogin: {r.status_code} - {r.text}")
            return None
    except Exception as e:
        print(f"حدث خطأ في xJwT: {str(e)}")
        return None

def generate_jwt_from_data(open_id, access_token):
    """واجهة مبسطة لتوليد JWT باستخدام open_id و access_token مباشرة"""
    return xJwT(access_token, open_id)

# =================== الاستخدام المباشر ===================
if __name__ == "__main__":
    # البيانات التي أرفقتها (OB53)
    OPEN_ID = "4306245793de86da425a52caadf21eed"
    ACCESS_TOKEN = "c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94"
    
    jwt = generate_jwt_from_data(OPEN_ID, ACCESS_TOKEN)
    if jwt:
        print("\n" + "="*50)
        print("JWT الناتج:")
        print(jwt)
        print("="*50)
    else:
        print("فشل في الحصول على JWT.")