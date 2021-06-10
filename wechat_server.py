import web
import hashlib
import xml.etree.ElementTree as ET
import base64
from Crypto.Cipher import AES
import socket
import struct
import time
import string
import random

AES_TEXT_RESPONSE_TEMPLATE = """<xml>
<Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>
<MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>
<TimeStamp>%(timestamp)s</TimeStamp>
<Nonce><![CDATA[%(nonce)s]]></Nonce>
</xml>"""

urls = (
    '/v1/mp/msg/push/funnywheel', 'WxHandler',
)

app_id = '1234'
mp_token = 'xxxx'
encrypt_key = base64.b64decode('xxxx' + '=')
assert len(encrypt_key) == 32


def decrypt(encrypt_data):
    try:
        cryptor = AES.new(encrypt_key, AES.MODE_CBC, encrypt_key[:16])
        plain_text = cryptor.decrypt(base64.b64decode(encrypt_data))
    except Exception:
        print('decrypt failed')
        return False

    print("plan_text=" + str(plain_text))
    pad = ord(chr(plain_text[-1]))
    content = plain_text[16:-pad]
    xml_len = socket.ntohl(struct.unpack("I", content[: 4])[0])
    xml_content = content[4: xml_len+4].decode('utf-8')
    from_appid = content[xml_len+4:].decode('utf-8')
    return (from_appid, xml_content)


def encrypt(text, appid):
    block_size = 32
    text = generate_random_str() + struct.pack("I", socket.htonl(len(text))
                                               ).decode('utf-8') + text + appid
    text_length = len(text)
    amount_to_pad = block_size - (text_length % block_size)
    if amount_to_pad == 0:
        amount_to_pad = block_size
    pad = chr(amount_to_pad)
    text = text + pad * amount_to_pad
    cryptor = AES.new(encrypt_key, AES.MODE_CBC, encrypt_key[:16])
    ciphertext = cryptor.encrypt(text)
    return base64.b64encode(ciphertext)


def generate_random_str():
    rule = string.ascii_letters + string.digits
    str = random.sample(rule, 16)
    return "".join(str)


def generate_encrypted_xml(encrypted_msg, nonce):
    timestamp = str(int(time.time()))
    signature = generate_signature(mp_token, timestamp, nonce, encrypted_msg)
    resp_dict = {
        'msg_encrypt': encrypted_msg,
        'msg_signaturet': signature,
        'timestamp': timestamp,
        'nonce': nonce,
    }
    return AES_TEXT_RESPONSE_TEMPLATE % resp_dict


def extract_from_xml(data):
    root = ET.fromstring(data)
    encrypt_data = None
    touser_name = None
    for child in root:
        if child.tag == 'Encrypt':
            encrypt_data = child.text
            continue
        elif child.tag == 'ToUserName':
            touser_name = child.text
            continue
    return (touser_name, encrypt_data)


def generate_sha1(text):
    sha1 = hashlib.sha1(text.encode("utf-8"))
    return sha1.hexdigest()


def generate_signature(token, timestamp, nonce, encrypted_data):
    sortlist = [token, timestamp, nonce, encrypted_data]
    sortlist.sort()
    return generate_sha1("".join(sortlist))


class WxHandler(object):
    def GET(self):
        data = web.input()
        if len(data) == 0:
            return "hello, this is handle view"
        signature = data.signature
        timestamp = data.timestamp
        nonce = data.nonce
        echostr = data.echostr
        print("signature=" + signature + ", timestamp=" +
              timestamp + ", nonce=" + nonce + ", echostr=" + echostr)
        array = [mp_token, timestamp, nonce]
        array.sort()
        tmp_str = ''.join(array)
        hashcode = generate_sha1(tmp_str)
        print("handle/GET func: hashcode=" +
              hashcode + ", signature=" + signature)
        if hashcode == signature:
            return echostr
        else:
            return ""

    def POST(self):
        params = web.input()
        data = web.data()
        data = data.decode()
        param_timestamp = params.timestamp
        param_nonce = params.nonce
        param_msg_signature = params.msg_signature
        print("params=" + str(params) + ", data=" + data)

        origin_xml_tuple = extract_from_xml(data)
        touser_name = origin_xml_tuple[0]
        encrypt_data = origin_xml_tuple[1]

        hashcode = generate_signature(
            mp_token, param_timestamp, param_nonce, encrypt_data)
        print("computed signature=" + hashcode)
        if not param_msg_signature == hashcode:
            print('signature not matched')
            return False

        decrypted_tuple = decrypt(encrypt_data)
        print("decrypted_tuple=" + str(decrypted_tuple))
        from_appid = decrypted_tuple[0]
        xml_content = decrypted_tuple[1]
        if (from_appid == app_id):
            encrypt_msg = encrypt(
                "<xml><result>ok</result></xml>", app_id).decode('utf-8')
            print("encrypt_msg=" + encrypt_msg)
            response = generate_encrypted_xml(
                encrypt_msg, generate_random_str())
            print("response=" + response)
            return response
        else:
            return False


if __name__ == '__main__':
    app = web.application(urls, globals())
    app.run()
