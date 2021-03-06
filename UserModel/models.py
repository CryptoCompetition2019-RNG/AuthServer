from django.db import models


# Create your models here.
class UserModel(models.Model):
    user_name = models.CharField(
        max_length=64,
        unique=True,
        help_text=u"最长128个字符，用户唯一标示，但不是主键",
        verbose_name=u"用户名"
    )
    hash_IMEI = models.CharField(
        max_length=64,
        # unique=True,
        help_text=u"手机标示码的哈希值，要求唯一标示（应当选取一个避免哈希碰撞的函数）",
        verbose_name=u"IMEI码哈希值"
    )
    salt = models.CharField(
        max_length=64,
        help_text=u"这个盐值会随 timestamp 变化",
        verbose_name=u"盐值"
    )
    A_pwd = models.CharField(max_length=64, )
    B_pwd = models.CharField(max_length=64, )

    # temporary field
    random_value1 = models.CharField(max_length=64, null=True, blank=True)
    random_value2 = models.CharField(max_length=64, null=True, blank=True)
    random_value3 = models.CharField(max_length=64, null=True, blank=True)

    login_status = models.BooleanField(default=False, null=True)

    def get_salt_sm4_key(self) -> bytes:
        from Crypto.Util.number import long_to_bytes
        return long_to_bytes(int(self.salt[:32].ljust(32, '\x00'), 16))
