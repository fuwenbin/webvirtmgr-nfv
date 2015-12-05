from string import letters, digits
from random import choice
from bisect import insort

from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect, HttpResponse
from django.template import RequestContext
from django.utils.translation import ugettext_lazy as _
from django.core.urlresolvers import reverse
import json
import time

from instance.models import Instance
from servers.models import Compute

from vrtManager.instance import wvmInstances, wvmInstance

from libvirt import libvirtError, VIR_DOMAIN_XML_SECURE
from webvirtmgr.settings import TIME_JS_REFRESH, QEMU_KEYMAPS, QEMU_CONSOLE_TYPES
from vrtManager.interface import wvmInterface, wvmInterfaces
from vrtManager import util
import os
from vrtManager.storage import wvmStorage, wvmStorages
from webvirtmgr import settings
import re
from mac.models import Mac
from vrtManager import util
def mac(request, host_id):
    """
    Return instance usage
    """
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('login'))
    compute = Compute.objects.get(id=host_id)
    import os
    if not os.path.exists(settings.mac_save_dir):
        os.mkdir(settings.mac_save_dir)
    dest = open(settings.mac_save_dir+"mac",'w+')
    regex = re.compile("([0-9a-fA-F]{2})(([-:][0-9a-fA-F]{2}){5})$")
    if request.method == 'POST':
        if 'mac_upload' in request.POST:
            list_lines = request.FILES['file'].read().split('\r\n')
            for line in list_lines:
                result = regex.match(line)
                if result:
                    util.set_mac_for_vf()
                    dest.write(line)
                    dest.write('\r\n')
            dest.flush()
            dest.close()
            util.set_mac_for_vf()
            print list_lines
    total_mac_cnt,success_mac = util.get_totalmac_setmac()
    return render_to_response('macload.html', locals(), context_instance=RequestContext(request))


