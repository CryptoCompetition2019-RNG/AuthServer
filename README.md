# AuthServer
服务端

## 问题

### 我觉得协议设计存在的一些问题

1. 在注册阶段，无法对用户的有效性进行识别。也就是说，我们无法避免用户不断地伪造大量用户进行注册。

   这一问题传统的解决方式是发送验证码，手机验证码或邮箱验证码。

2. PC 端协议设计还有存在一些问题；

3. 移动端登陆存在 salt 被窃取的风险；

4. 动态登陆也存在 salt 被窃取的风险，QRCode 是个什么样的数据类型不太理解；

### 我觉得需要在 PPT 中补充的一些问题

1. DH 密钥交换的流程，需要体现出来。

2. 协议设计细节：DH 密钥是：

   ```
   long_to_bytes(共享秘密信息)[:64].rjust(64, b'\x00')
   ```

3. 请求过程中数字类型数据，应该显示地指明它应当如何转化为字符串；

### 服务端还存在一些问题

1. 数据库设计强制让某些表项满足一定的长度