from AuthServer.method import json_response_zh, get_json_ret, encrypt_ecb, decrypt_ecb
from Crypto.Util.number import getRandomNBitInteger, long_to_bytes

from .models import UserModel


def mobileauth_api1(request):
    """
    移动端进行验证的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') )}
    :return: 如果一切验证成功，则正常应该返回下面的内容：
        {"data": sm4_{salt}( r2 + A_pwd )}
    """
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))
    if len(data) != 64:
        return json_response_zh(get_json_ret(41))

    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    user_name = decrypt_ecb(DH_key, data).rstrip(b'\x00')
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    user.random_value2 = long_to_bytes(getRandomNBitInteger(64))
    user.save()
    ret_data = encrypt_ecb(user.salt, user.random_value2 + user.A_pwd)
    return json_response_zh(get_json_ret(0, data=ret_data))


def mobileauth_api2(request):
    """
    移动端验证口令的第二步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据
        {"data": sm4_{DH_key}( hex(r2) + B_pwd* )}
    :return: B_pwd* 与 B_pwd 是否相等
    """
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))
    if len(data) != 64 * 2:
        return json_response_zh(get_json_ret(41))

    user_name = request.session.get('user_name')
    if user_name is None:
        return json_response_zh(get_json_ret(42))
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(42))

    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    plain = decrypt_ecb(DH_key, data)
    if plain[:64] != user.random_value2:
        return json_response_zh(get_json_ret(50, msg="随机数错误"))
    user.random_value2 = None
    user.save()
    return json_response_zh(get_json_ret(0 if plain[64:] == user.B_pwd else 50))
