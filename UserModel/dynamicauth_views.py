from django.http import HttpResponse
from AuthServer.method import json_response_zh, get_json_ret, encrypt_ecb, decrypt_ecb, make_qrcode

from .models import UserModel


def dynamicauth_api1(request):
    """
    动态二维码验证的第一步
    :param request: 一个有效的请求应该包含形如以下的 POST 数据：
        {"data": sm4_{DH_key}( id.ljust(64, '\x00') )}
    :return:
    """
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))
    if len(data) != 64:
        return json_response_zh(get_json_ret(41))

    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    user_name = decrypt_ecb(DH_key, data)
    user = UserModel.objects.get(user_name=user_name)
    if user is None:
        return json_response_zh(get_json_ret(41))
    request.session['user_name'] = user_name

    from Crypto.Util.number import long_to_bytes, getRandomNBitInteger
    user.random_value3 = long_to_bytes(getRandomNBitInteger(64))
    user.save()
    qr_value = encrypt_ecb(user.salt, user.random_value3 + user.user_name)
    return HttpResponse(make_qrcode(qr_value), content_type='image/jpeg')


def dynamicauth_api2(request):
    return json_response_zh({'msg': 'dynamicauth_Api2'})
