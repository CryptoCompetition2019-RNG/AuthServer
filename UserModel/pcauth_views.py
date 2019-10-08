from django.views.decorators.http import require_POST
from AuthServer.method import json_response_zh, get_json_ret
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from Crypto.Util.number import long_to_bytes

from .models import UserModel


@require_POST
def pcauth_api1(request):
    """
    PC 端验证口令的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') ) + sm4_{salt}( hex(r1) ) }
    :return: data 内容通过以下方式计算 sm4_{DH_key}(r1, A_pwd)
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
    user_name = crypt_sm4.crypt_ecb(data[:64])
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    sm4_key = long_to_bytes(user.salt)[:64].rjust(64, b'\x00')
    crypt_sm4 = CryptSM4(SM4_DECRYPT)
    crypt_sm4.set_key(sm4_key, SM4_DECRYPT)
    r1 = crypt_sm4.crypt_ecb(data[64:])

    sm4_key = long_to_bytes(DH_key)[:64].rjust(64, b'\x00')
    crypt_sm4 = CryptSM4(SM4_ENCRYPT)
    crypt_sm4.set_key(sm4_key, SM4_ENCRYPT)
    ret_data = crypt_sm4.crypt_ecb(r1 + user.A_pwd)
    return json_response_zh(get_json_ret(0, data=ret_data))


def pcauth_api2(request):
    """
    PC 端验证口令的第二步
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
