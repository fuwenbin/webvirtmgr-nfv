from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.utils.translation import ugettext_lazy as _
from django.core.urlresolvers import reverse

from servers.models import Compute
from create.models import Flavor
from instance.models import Instance

from libvirt import libvirtError

from vrtManager.create import wvmCreate
from vrtManager import util
from create.forms import FlavorAddForm, NewVMForm
from vrtManager.interface import wvmInterface, wvmInterfaces

import commands
import os
import logging


def create(request, host_id):
    """
    Create new instance.
    """
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('login'))

    conn = None
    errors = []
    ifaces_all = []
    ifaces_all_name = ""
    storages = []
    hd_resources = {}
    meta_prealloc = False
    compute = Compute.objects.get(id=host_id)
    flavors = Flavor.objects.filter().order_by('id')
    flavor_name_list = Flavor.objects.filter(label='label')
    memory_range = [2048, 4096, 6144, 8192, 16384]
    vcpu_range = None

    try:
        conn = wvmCreate(compute.hostname,
                         compute.login,
                         compute.password,
                         compute.type)
        conn_interfaces = wvmInterfaces(compute.hostname,
                             compute.login,
                             compute.password,
                             compute.type)
        ifaces = conn_interfaces.get_ifaces()
        storages = sorted(conn.get_storages())
        instances = conn.get_instances()
        get_images = sorted(conn.get_storages_images())

        if os.path.exists(util.get_hd_resources_conf()):
            hd_resources = util.load_hd_resources()
            mem_left = hd_resources["mem"]
            vcpu_left = hd_resources["vcpu"]
            hd_resources = util.filter_hd_resources(hd_resources)
        else:
            hd_resources = util.create_hd_resources()
            mem_left = hd_resources["mem"]
            vcpu_left = hd_resources["vcpu"]
            hd_resources = util.filter_hd_resources(hd_resources)
        memory_range = [ memory for memory in memory_range if memory/1024 <= mem_left ]
        vcpu_range = xrange(1, int(vcpu_left) + 1)

    except libvirtError as err:
        errors.append(err)

    if conn_interfaces:
        try:
            netdevs = conn_interfaces.get_net_device()
        except:
            netdevs = ['eth0', 'eth1'] 

    if conn:
        if not storages:
            msg = _("You haven't defined have any storage pools")
            errors.append(msg)

        if request.method == 'POST':
            if 'create_flavor' in request.POST:
                form = FlavorAddForm(request.POST)
                if form.is_valid():
                    data = form.cleaned_data
                    flavor_name_list = Flavor.objects.filter(label=data['label'])
                    if flavor_name_list:
                        msg = _("A virtual machine template with this name already exists")
                        errors.append(msg)
                    else:
                        create_flavor = Flavor(label=data['label'],
                                           vcpu=data['vcpu'],
                                           memory=data['memory'],
                                           disk=data['disk'])
                        create_flavor.save()
                        return HttpResponseRedirect(request.get_full_path())
            if 'delete_flavor' in request.POST:
                flavor_id = request.POST.get('flavor', '')
                delete_flavor = Flavor.objects.get(id=flavor_id)
                delete_flavor.delete()
                return HttpResponseRedirect(request.get_full_path())
            if 'create_xml' in request.POST:
                xml = request.POST.get('from_xml', '')
                try:
                    name = util.get_xml_path(xml, '/domain/name')
                except util.libxml2.parserError:
                    name = None
                if name in instances:
                    msg = _("A virtual machine with this name already exists")
                    errors.append(msg)
                else:
                    try:
                        conn._defineXML(xml)
                        return HttpResponseRedirect(reverse('instance', args=[host_id, name]))
                    except libvirtError as err:
                        errors.append(err.message)
            if 'create' in request.POST:
                
                volumes = {}
                interfaces = []
                vm_vfs_info = {}
                form = NewVMForm(request.POST)
                if form.is_valid():
                    data = form.cleaned_data
                    if instances:
                        if data['name'] in instances:
                            msg = _("A virtual machine with this name already exists")
                            errors.append(msg)
                    if not errors:
                        
                        if data['hdd_size']:
                            try:
                                path = conn.create_volume(data['storage'], data['name'], data['hdd_size'],
                                                          metadata=meta_prealloc)
                                volumes[path] = conn.get_volume_type(path)
                            except libvirtError as msg_error:
                                errors.append(msg_error.message)
                        elif data['template']:
                            templ_path = conn.get_volume_path(data['template'])
                            clone_path = conn.clone_from_template(data['name'], templ_path, metadata=meta_prealloc)
                            volumes[clone_path] = conn.get_volume_type(clone_path)

                            ifaces_all = request.POST.getlist('interfaces')
                        else:
                            if not data['images']:
                                msg = _("First you need to create or select an image")
                                errors.append(msg)
                            else:
                                for vol in data['images'].split(','):
                                    try:
                                        path = conn.get_volume_path(vol)
                                        volumes[path] = conn.get_volume_type(path)
                                    except libvirtError as msg_error:
                                        errors.append(msg_error.message)
                            
                        if not errors:
                            uuid = util.randomUUID()
                            try:
                                template_ver3_flag = True
                                if data['template'].find("WiseGrid_V3") == -1:
                                    template_ver3_flag = False

                                conn.create_instance(data['name'], data['cur_memory'], data['cur_vcpu'], 
                                                     uuid, volumes, ifaces_all, False, True, template_ver3_flag)
                                create_instance = Instance(compute_id=host_id, name=data['name'], uuid=uuid)
                                create_instance.save()
                                vm_vfs_info[data['name']] = ifaces_all
                                if not errors:
                                   util.update_vfs_fro_vm(vm_vfs_info)
                                return HttpResponseRedirect(reverse('instance', args=[host_id, data['name']]))
                            except libvirtError as err:
                                if data['hdd_size']:
                                    conn.delete_volume(volumes.keys()[0])
                                errors.append(err)
                else:
                    print form.errors
                    errors.append(form.errors)
        conn.close()
        return HttpResponseRedirect(reverse('instances',args=[host_id,errors]))
#    return render_to_response('create.html', locals(), context_instance=RequestContext(request))
