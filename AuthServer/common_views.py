from django.views.decorators.http import require_POST
from Crypto.Util.number import getPrime, long_to_bytes

from .method import json_response_zh, get_json_ret


@require_POST
def negotiate_key1(request):
    """
    实现 DH 密钥交换的 API 的第一步，会生成一个 1024 位的随机密钥
    :param request: POST 请求
    :return: 服务端选择 p 和 g 存储进入 session，并且 json 返回；
    """
    DH_g, DH_p = 5, getPrime(128)
    request.session['DH_g'] = DH_g
    request.session['DH_p'] = DH_p
    return json_response_zh(get_json_ret(0, data={"p": hex(DH_g), "g": hex(DH_p)}))


@require_POST
def negotiate_key2(request):
    """
    实现 DH 密钥交换 API 的第二步，这一步会生成服务器端的秘密信息，计算会话密钥后存入 session
    :param request: data 内容被认为是十六进制的 g^speer % p
    :return: 返回的 data 中是十六进制的 g^sthis % p
    """
    try:
        data = int(request.POST.get("data"), 16)
        DH_g, DH_p = request.session.get('DH_g'), request.session.get('DH_p')
        assert DH_p is not None and DH_g is not None
    except TypeError:
        return json_response_zh(get_json_ret(40))
    except ValueError:
        return json_response_zh(get_json_ret(41))
    except AssertionError:
        return json_response_zh(get_json_ret(42))

    secret = getPrime(64)
    request.session['DH_key'] = long_to_bytes(pow(data, secret, DH_p))[:64].rjust(64, b'\x00')
    return json_response_zh(get_json_ret(0, data={
        'data': hex(pow(DH_g, secret, DH_p))
    }))