from AuthServer.method import json_response_zh, get_json_ret
from Crypto.Util.number import long_to_bytes
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

from .models import UserModel

def mobileauth_api1(request):
    """
    移动端进行验证的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') + r2 )}
    :return: 如果一切验证成功，则正常应该返回下面的内容：
        {"data": sm4_{DH_key}( r2 + A_pwd + salt )}
    """
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))
    if len(data) != 64 * 2:
        return json_response_zh(get_json_ret(41))

    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    sm4_key = long_to_bytes(DH_key)[:64].rjust(64, b'\x00')
    crypt_sm4 = CryptSM4(SM4_DECRYPT)
    crypt_sm4.set_key(sm4_key, SM4_DECRYPT)
    plain = crypt_sm4.crypt_ecb(data).rstrip('\x00')

    user_name, r2 = plain[:64].rstrip('\x00'), plain[64:]
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    sm4_key = long_to_bytes(DH_key)[:64].rjust(64, b'\x00')
    crypt_sm4 = CryptSM4(SM4_ENCRYPT)
    crypt_sm4.set_key(sm4_key, SM4_ENCRYPT)
    ret_data = crypt_sm4.crypt_ecb(r2 + user.A_pwd + user.salt)
    return json_response_zh(get_json_ret(0, data=ret_data))


def mobileauth_api2(request):
    """
    移动端验证口令的第二步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据
        {"data": sm4_{DH_key}( hex(r1+1) + B_pwd*)}
    :return: B_pwd* 与 B_pwd 是否相等
    """
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))
    if len(data) != 64 * 2:
        return json_response_zh(get_json_ret(41))

    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    sm4_key = long_to_bytes(DH_key)[:64].rjust(64, b'\x00')
    crypt_sm4 = CryptSM4(SM4_DECRYPT)
    crypt_sm4.set_key(sm4_key, SM4_DECRYPT)
    B_pwd = crypt_sm4.crypt_ecb(data)[:64]

    user_name = request.session.get('user_name')
    if user_name is None:
        return json_response_zh(get_json_ret(42))
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(42))

    return json_response_zh(get_json_ret(0, data=(B_pwd == user.B_pwd)))
