from django.db import models
from servers.models import Compute


class Mac(models.Model):
    used = models.CharField(max_length=2,default='0')
    mac_addr = models.CharField(max_length=36)

    def __unicode__(self):
        return self.mac_addr
