from django.http import HttpResponse
from AuthServer.method import json_response_zh, get_json_ret, encrypt_ecb, decrypt_ecb, make_qrcode

from .models import UserModel


def dynamicauth_api1(request):
    """
    动态二维码验证的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') )}
    :return: 返回一个图片，图片包含的字符串信息是：sm4_{salt}(r3)
    """
    if len(request.data) != 64:
        return json_response_zh(get_json_ret(41))

    user_name = decrypt_ecb(request.DH_key, request.data)
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    from Crypto.Util.number import long_to_bytes, getRandomNBitInteger
    user.random_value3 = long_to_bytes(getRandomNBitInteger(64))
    user.save()
    qr_value = encrypt_ecb(user.salt, user.random_value3)
    return HttpResponse(make_qrcode(qr_value), content_type='image/jpeg')


def dynamicauth_api2(request):
    """
    动态二维码验证的第二步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') + H(IMEI) + r3 )}
    :return: 如果所有检查成功，则会返回 0 表示登录成功，但是这个信号并不会传递到手机上
    """
    if len(request.data) != 64 * 3:
        return json_response_zh(get_json_ret(41))

    plain = decrypt_ecb(request.DH_key, request.data)
    user_name = plain[:64].rstrip('\x00')
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    if user.hash_IMEI != plain[64: 64 * 2]:
        return json_response_zh(get_json_ret(50, msg="手机 IMEI 码验证失败"))
    if user.random_value3 != plain[64 * 2: 64 * 3]:
        return json_response_zh(get_json_ret(50, msg="随机数验证错误"))
    user.random_value3 = None
    user.save()
    request.session['is_login'] = True
    return json_response_zh(get_json_ret(0, msg='登录成功'))


def dynamicauth_api3(request):
    """
    动态二维码验证的第三步，PC 端检查自己是否登录成功
    """
    return json_response_zh(get_json_ret(0 if request.session.get('is_login') else 51))
