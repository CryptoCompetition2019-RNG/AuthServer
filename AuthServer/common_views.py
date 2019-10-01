from django.views.decorators.http import require_POST
from Crypto.Util.number import getPrime

from .method import json_response_zh, get_json_ret


@require_POST
def negotiate_key(request):
    """
    实现 DH 密钥交换的 API
    :param request: 有效的请求应该包含一个形如以下实例的 post 数据：
        {"step": "1/2", "data": "*****"}
    :return:
        如果是 step1，服务端选择 p 和 g 存储进入 session，并且 json 返回；
        如果是 step2，data 内容被认为是 g^speer % p，它计算会话密钥存入 session 后，返回 g^sthis % p
    """
    step = request.POST.get("step")
    if step is None:
        return json_response_zh(get_json_ret(40))
    elif step == "1":
        DH_g, DH_p = 0x10001, getPrime(1024)
        request.session['DH_g'] = DH_g
        request.session['DH_p'] = DH_p
        return json_response_zh(get_json_ret(0, data={"p": hex(DH_g), "g": hex(DH_p)}))
    elif step == "2":
        try:
            data = int(request.POST.get("data"))
            DH_g, DH_p = request.session.get('DH_g'), request.session.get('DH_p')
            assert DH_p is not None and DH_g is not None
        except TypeError:
            return json_response_zh(get_json_ret(40))
        except ValueError:
            return json_response_zh(get_json_ret(41))
        except AssertionError:
            return json_response_zh(get_json_ret(42))

        secret = getPrime(1024)
        request.session['DH_key'] = pow(data, secret, DH_p)
        return json_response_zh(get_json_ret(0, data={
            'data': hex(pow(DH_g, secret, DH_p))
        }))
    else:
        return json_response_zh(get_json_ret(41))
