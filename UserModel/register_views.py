from django.views.decorators.http import require_POST
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from Crypto.Util.number import long_to_bytes

from AuthServer.method import json_response_zh, get_json_ret
from .models import UserModel


@require_POST
def register_api(request):
    """
    实现注册功能的 API
    :param request: 有效的请求应该包含一个形如以下实例的 post 数据：
        {"data": sm4( id.ljust(64, '\x00') + A_pwd + A_e + B_pwd + B_e + sm3(IMEI) )}
    :return: 如果失败，则会返回相对应的错误码；如果成功返回 0
    """
    DH_key = request.session['DH_key']
    if DH_key is None:
        return json_response_zh(get_json_ret(42))
    data = request.POST.get("data")
    if data is None:
        return json_response_zh(get_json_ret(40))

    sm4_key = long_to_bytes(DH_key)[:64].rjust(64, b'\x00')
    crypt_sm4 = CryptSM4(SM4_DECRYPT)
    crypt_sm4.set_key(sm4_key, SM4_DECRYPT)
    plain = crypt_sm4.crypt_ecb(data)
    if len(plain) != 64 * 5:
        return json_response_zh(get_json_ret(41))

    UserModel.objects.create(
        user_name=plain[:64].rstrip('\x00'),
        salt=plain[64:64 * 2],
        A_pwd=plain[64 * 2:64 * 3],
        B_pwd=plain[64 * 3:64 * 4],
        hash_IMEI=plain[64 * 4:64 * 5]
    )
    return json_response_zh(get_json_ret(0))
