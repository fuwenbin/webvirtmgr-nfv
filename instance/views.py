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
def instusage(request, host_id, vname):
    """
    Return instance usage
    """
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('login'))

    cookies = {}
    datasets = {}
    datasets_rd = []
    datasets_wr = []
    json_blk = []
    cookie_blk = {}
    blk_error = False
    datasets_rx = []
    datasets_tx = []
    json_net = []
    cookie_net = {}
    net_error = False
    points = 5
    curent_time = time.strftime("%H:%M:%S")
    compute = Compute.objects.get(id=host_id)
    cookies = request._get_cookies()
    response = HttpResponse()
    response['Content-Type'] = "text/javascript"

    try:
        conn = wvmInstance(compute.hostname,
                           compute.login,
                           compute.password,
                           compute.type,
                           vname)
        cpu_usage = conn.cpu_usage()
        blk_usage = conn.disk_usage()
        net_usage = conn.net_usage()
        conn.close()

        if cookies.get('cpu') == '{}' or not cookies.get('cpu') or not cpu_usage:
            datasets['cpu'] = [0]
            datasets['timer'] = [curent_time]
        else:
            datasets['cpu'] = eval(cookies.get('cpu'))
            datasets['timer'] = eval(cookies.get('timer'))

        datasets['timer'].append(curent_time)
        datasets['cpu'].append(int(cpu_usage['cpu']))

        if len(datasets['timer']) > points:
            datasets['timer'].pop(0)
        if len(datasets['cpu']) > points:
            datasets['cpu'].pop(0)

        cpu = {
            'labels': datasets['timer'],
            'datasets': [
                {
                    "fillColor": "rgba(241,72,70,0.5)",
                    "strokeColor": "rgba(241,72,70,1)",
                    "pointColor": "rgba(241,72,70,1)",
                    "pointStrokeColor": "#fff",
                    "data": datasets['cpu']
                }
            ]
        }

        for blk in blk_usage:
            if cookies.get('hdd') == '{}' or not cookies.get('hdd') or not blk_usage:
                datasets_wr.append(0)
                datasets_rd.append(0)
            else:
                datasets['hdd'] = eval(cookies.get('hdd'))
                try:
                    datasets_rd = datasets['hdd'][blk['dev']][0]
                    datasets_wr = datasets['hdd'][blk['dev']][1]
                except:
                    blk_error = True

            if not blk_error:
                datasets_rd.append(int(blk['rd']) / 1048576)
                datasets_wr.append(int(blk['wr']) / 1048576)

                if len(datasets_rd) > points:
                    datasets_rd.pop(0)
                if len(datasets_wr) > points:
                    datasets_wr.pop(0)

                disk = {
                    'labels': datasets['timer'],
                    'datasets': [
                        {
                            "fillColor": "rgba(83,191,189,0.5)",
                            "strokeColor": "rgba(83,191,189,1)",
                            "pointColor": "rgba(83,191,189,1)",
                            "pointStrokeColor": "#fff",
                            "data": datasets_rd
                        },
                        {
                            "fillColor": "rgba(249,134,33,0.5)",
                            "strokeColor": "rgba(249,134,33,1)",
                            "pointColor": "rgba(249,134,33,1)",
                            "pointStrokeColor": "#fff",
                            "data": datasets_wr
                        },
                    ]
                }

            json_blk.append({'dev': blk['dev'], 'data': disk})
            cookie_blk[blk['dev']] = [datasets_rd, datasets_wr]

        for net in net_usage:
            if cookies.get('net') == '{}' or not cookies.get('net') or not net_usage:
                datasets_rx.append(0)
                datasets_tx.append(0)
            else:
                datasets['net'] = eval(cookies.get('net'))
                try:
                    datasets_rx = datasets['net'][net['dev']][0]
                    datasets_tx = datasets['net'][net['dev']][1]
                except:
                    net_error = True

            if not net_error:
                datasets_rx.append(int(net['rx']) / 1048576)
                datasets_tx.append(int(net['tx']) / 1048576)

                if len(datasets_rx) > points:
                    datasets_rx.pop(0)
                if len(datasets_tx) > points:
                    datasets_tx.pop(0)

                network = {
                    'labels': datasets['timer'],
                    'datasets': [
                        {
                            "fillColor": "rgba(83,191,189,0.5)",
                            "strokeColor": "rgba(83,191,189,1)",
                            "pointColor": "rgba(83,191,189,1)",
                            "pointStrokeColor": "#fff",
                            "data": datasets_rx
                        },
                        {
                            "fillColor": "rgba(151,187,205,0.5)",
                            "strokeColor": "rgba(151,187,205,1)",
                            "pointColor": "rgba(151,187,205,1)",
                            "pointStrokeColor": "#fff",
                            "data": datasets_tx
                        },
                    ]
                }

            json_net.append({'dev': net['dev'], 'data': network})
            cookie_net[net['dev']] = [datasets_rx, datasets_tx]

        data = json.dumps({'cpu': cpu, 'hdd': json_blk, 'net': json_net})
        response.cookies['cpu'] = datasets['cpu']
        response.cookies['timer'] = datasets['timer']
        response.cookies['hdd'] = cookie_blk
        response.cookies['net'] = cookie_net
        response.write(data)
    except libvirtError:
        data = json.dumps({'error': 'Error 500'})
        response.write(data)
    return response


def inst_status(request, host_id, vname):
    """
    Instance block
    """
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('login'))

    compute = Compute.objects.get(id=host_id)

    try:
        conn = wvmInstance(compute.hostname,
                           compute.login,
                           compute.password,
                           compute.type,
                           vname)
        status = conn.get_status()
        conn.close()
    except libvirtError:
        status = None

    data = json.dumps({'status': status})
    response = HttpResponse()
    response['Content-Type'] = "text/javascript"
    response.write(data)
    return response


def insts_status(request, host_id):
    """
    Instances block
    """
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('login'))

    errors = []
    instances = []
    compute = Compute.objects.get(id=host_id)

    try:
        conn = wvmInstances(compute.hostname,
                            compute.login,
                            compute.password,
                            compute.type)
        get_instances = conn.get_instances()
    except libvirtError as err:
        errors.append(err)

    for instance in get_instances:
        instances.append({'name': instance,
                          'status': conn.get_instance_status(instance),
                          'memory': conn.get_instance_memory(instance),
                          'vcpu': conn.get_instance_vcpu(instance),
                          'uuid': conn.get_uuid(instance),
                          'host': host_id,
                          'dump': conn.get_instance_managed_save_image(instance)
                          })

    data = json.dumps(instances)
    response = HttpResponse()
    response['Content-Type'] = "text/javascript"
    response.write(data)
    return response

from webvirtmgr import settings
from vrtManager.create import wvmCreate
from create.forms import FlavorAddForm, NewVMForm
def instances(request, host_id):
    """
    Instances block
    """
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('login'))

    errors = []
    instances = []
    time_refresh = 8000
    get_instances = []
    cnt_max = settings.vf_cnt_max
    conn = None
    meta_prealloc = False
    compute = Compute.objects.get(id=host_id)
    memory_range = [2048, 4096, 6144, 8192, 16384]
    ifaces_all = util.get_free_vfs()
    ifaces_all = sorted(ifaces_all.iteritems(),key=lambda ax:ax[0])

    try:
        conn = wvmInstances(compute.hostname,
                            compute.login,
                            compute.password,
                            compute.type)
        conn_create = wvmCreate(compute.hostname,
                         compute.login,
                         compute.password,
                         compute.type)
        conn_storage = wvmStorage(compute.hostname,
                          compute.login,
                          compute.password,
                          compute.type,
                          'Images')
        state = conn_storage.is_active()
        if state:
            conn_storage.refresh()
            volumes = conn_storage.update_volumes()
            conn_storage.close()
        else:
            volumes = None
        get_images = volumes
        get_instances = conn.get_instances()
    except libvirtError as err:
        pass
#        errors.append(err)

    for instance in get_instances:
        try:
            inst = Instance.objects.get(compute_id=host_id, name=instance)
            uuid = inst.uuid
        except Instance.DoesNotExist:
            uuid = conn.get_uuid(instance)
            inst = Instance(compute_id=host_id, name=instance, uuid=uuid)
            inst.save()
        instances.append({'name': instance,
                          'status': conn.get_instance_status(instance),
                          'uuid': uuid,
                          'memory': conn.get_instance_memory(instance),
                          'vcpu': conn.get_instance_vcpu(instance),
                          'has_managed_save_image': conn.get_instance_managed_save_image(instance)})
    if conn:
        try:
            if request.method == 'POST':
                name = request.POST.get('name', '')
                if 'start' in request.POST:
                    conn.start(name)
                    return HttpResponseRedirect(request.get_full_path())
                if 'shutdown' in request.POST:
                    conn.shutdown(name)
                    return HttpResponseRedirect(request.get_full_path())
                if 'destroy' in request.POST:
                    conn.force_shutdown(name)
                    return HttpResponseRedirect(request.get_full_path())
                if 'managedsave' in request.POST:
                    conn.managedsave(name)
                    return HttpResponseRedirect(request.get_full_path())
                if 'deletesaveimage' in request.POST:
                    conn.managed_save_remove(name)
                    return HttpResponseRedirect(request.get_full_path())
                if 'suspend' in request.POST:
                    conn.suspend(name)
                    return HttpResponseRedirect(request.get_full_path())
                if 'resume' in request.POST:
                    conn.resume(name)
                    return HttpResponseRedirect(request.get_full_path())
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
                                templ_path = conn_create.get_volume_path(data['template'])
                                clone_path = conn_create.clone_from_template(data['name'], templ_path, metadata=meta_prealloc)
                                volumes[clone_path] = conn_create.get_volume_type(clone_path)

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

                                    conn_create.create_instance(data['name'], data['cur_memory'], data['cur_vcpu'], 
                                                     uuid, volumes, ifaces_all, False, True, template_ver3_flag)
                                    create_instance = Instance(compute_id=host_id, name=data['name'], uuid=uuid)
                                    create_instance.save()
                                    vm_vfs_info[data['name']] = ifaces_all
                                    if not errors:
                                       util.update_vfs_fro_vm(vm_vfs_info)
                                    return HttpResponseRedirect(reverse('instance', args=[host_id, data['name']]))
                                except libvirtError as err:
                                    if data['hdd_size']:
                                        conn_create.delete_volume(volumes.keys()[0])
                                    errors.append(err)
                    else:
                        print form.errors
                        errors.append(form.errors)
            conn.close()
            conn_create.close()
        except libvirtError as err:
            errors.append(err)
        hd_resources = util.load_hd_resources()
        mem_left = hd_resources["mem"]
        vcpu_left = hd_resources["vcpu"]
        memory_range = [ memory for memory in memory_range if memory/1024 <= mem_left ]
        vcpu_range = xrange(1, int(vcpu_left) + 1)
        vcpu_memory_left_flag = True
        if len(list(vcpu_range)) == 0 or len(memory_range) == 0:
            vcpu_memory_left_flag = False
         
    return render_to_response('instances.html', locals(), context_instance=RequestContext(request))


def instance(request, host_id, vname):
    """
    Instance block
    """
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('login'))

    def show_clone_disk(disks):
        clone_disk = []
        for disk in disks:
            if disk['image'] is None:
                continue
            if disk['image'].count(".") and len(disk['image'].rsplit(".", 1)[1]) <= 7:
                name, suffix = disk['image'].rsplit(".", 1)
                image = name + "-clone" + "." + suffix
            else:
                image = disk['image'] + "-clone"
            clone_disk.append(
                {'dev': disk['dev'], 'storage': disk['storage'], 'image': image, 'format': disk['format']})
        return clone_disk

    errors = []
    messages = []
    time_refresh = TIME_JS_REFRESH * 3
    compute = Compute.objects.get(id=host_id)
    computes = Compute.objects.all()
    computes_count = len(computes)
    keymaps = QEMU_KEYMAPS
    console_types = QEMU_CONSOLE_TYPES
    
    try:
        conn = wvmInstance(compute.hostname,
                           compute.login,
                           compute.password,
                           compute.type,
                           vname)

        conn_interfaces = wvmInterfaces(compute.hostname,
                             compute.login,
                             compute.password,
                             compute.type)
        ifaces = conn_interfaces.get_ifaces()
        i = 0

        ifaces_all = util.get_free_vfs()
        ifaces_all = sorted(ifaces_all.iteritems(),key=lambda ax:ax[0])
        print ifaces_all
        temp_ifaces = []
        hd_resources = []
        hd_resources_checked = conn.get_hd_resources_device()
        if os.path.exists(util.get_hd_resources_conf()):
            hd_resources = util.load_hd_resources()
            for vf_filter in hd_resources.keys():
                if vf_filter == "mem" or vf_filter == "vcpu":
                        continue

                if hd_resources[vf_filter]['used'] == 1:
                    del hd_resources[vf_filter]
        else:
            hd_resources = util.create_hd_resources()

        vcpu_left = hd_resources["vcpu"]
        mem_left = hd_resources["mem"]
        del hd_resources["vcpu"]
        del hd_resources["mem"]
        
        
        is_vf = False
        status = conn.get_status()
        autostart = conn.get_autostart()
        vcpu = conn.get_vcpu()
        cur_vcpu = conn.get_cur_vcpu()
        uuid = conn.get_uuid()
        memory = conn.get_memory()
        cur_memory = conn.get_cur_memory()
        description = conn.get_description()
        disks = conn.get_disk_device()
        media = conn.get_media_device()
        networks = conn.get_net_device()
        hd_resources_checked = conn.get_hd_resources_device()
        media_iso = sorted(conn.get_iso_media())
        vcpu_range = conn.get_max_cpus()
        vcpu_max = vcpu_range
        vcpu_range = xrange(1, int(vcpu_left) + 1)
        memory_range = [2048, 4096, 6144, 8192, 16384]
        memory_range = [ memory for memory in memory_range if memory/1024 <= mem_left ]
        if memory not in memory_range:
            insort(memory_range, memory)
        if cur_memory not in memory_range:
            insort(memory_range, cur_memory)
        memory_host = conn.get_max_memory()
        vcpu_host = len(vcpu_max)
        telnet_port = conn.get_telnet_port()
        console_type = conn.get_console_type()
        console_port = conn.get_console_port()
        console_keymap = conn.get_console_keymap()
        snapshots = sorted(conn.get_snapshot(), reverse=True)
        inst_xml = conn._XMLDesc(VIR_DOMAIN_XML_SECURE)
        has_managed_save_image = conn.get_managed_save_image()
        clone_disks = show_clone_disk(disks)
        console_passwd = conn.get_console_passwd()
        vf_infos = util.get_pfvf_map(vname)
        if not vf_infos:
            vf_infos = {
			"test_pf1":[("vf1",'1.0.21'),('vf2','1.0.22')],
			"test_pf2":[("vf2",'1.0.31'),("vf3",'1.0.32')],
			"test_pf3":[("vf3",'1.0.41'),("vf5",'1.0.42')],
		    }
        try:
            instance = Instance.objects.get(compute_id=host_id, name=vname)
            if instance.uuid != uuid:
                instance.uuid = uuid
                instance.save()
        except Instance.DoesNotExist:
            instance = Instance(compute_id=host_id, name=vname, uuid=uuid)
            instance.save()
        if request.method == 'POST':
            if 'start' in request.POST:
                conn.start()
                return HttpResponseRedirect(request.get_full_path() + '#shutdown')
            if 'power' in request.POST:
                if 'shutdown' == request.POST.get('power', ''):
                    conn.shutdown()
                    return HttpResponseRedirect(request.get_full_path() + '#shutdown')
                if 'destroy' == request.POST.get('power', ''):
                    conn.force_shutdown()
                    return HttpResponseRedirect(request.get_full_path() + '#forceshutdown')
                if 'managedsave' == request.POST.get('power', ''):
                    conn.managedsave()
                    return HttpResponseRedirect(request.get_full_path() + '#managedsave')
            if 'deletesaveimage' in request.POST:
                conn.managed_save_remove()
                return HttpResponseRedirect(request.get_full_path() + '#managedsave')
            if 'suspend' in request.POST:
                conn.suspend()
                return HttpResponseRedirect(request.get_full_path() + '#suspend')
            if 'resume' in request.POST:
                conn.resume()
                return HttpResponseRedirect(request.get_full_path() + '#suspend')
            if 'delete' in request.POST:
                if conn.get_status() == 1:
                    conn.force_shutdown()
                try:
                    instance = Instance.objects.get(compute_id=host_id, name=vname)
                    instance.delete()
                    conn.delete_disk()

                    hd_resources_all = util.load_hd_resources()
                    for vf in hd_resources_checked:
                        hd_resources_all[vf]['used'] = 0
                    
                    hd_resources_all["vcpu"] = int(hd_resources_all["vcpu"]) + vcpu
                    hd_resources_all["mem"] = int(hd_resources_all["mem"]) + cur_memory / 1024
                    util.save_hd_resources(hd_resources_all)
             
                finally:
                    conn.delete()
                return HttpResponseRedirect(reverse('instances', args=[host_id]))
            if 'snapshot' in request.POST:
                name = request.POST.get('name', '')
                conn.create_snapshot(name)
                return HttpResponseRedirect(request.get_full_path() + '#istaceshapshosts')
            if 'umount_iso' in request.POST:
                image = request.POST.get('path', '')
                dev = request.POST.get('umount_iso', '')
                conn.umount_iso(dev, image)
                return HttpResponseRedirect(request.get_full_path() + '#instancemedia')
            if 'mount_iso' in request.POST:
                image = request.POST.get('media', '')
                dev = request.POST.get('mount_iso', '')
                conn.mount_iso(dev, image)
                return HttpResponseRedirect(request.get_full_path() + '#instancemedia')
            if 'set_autostart' in request.POST:
                conn.set_autostart(1)
                return HttpResponseRedirect(request.get_full_path() + '#instancesettings')
            if 'unset_autostart' in request.POST:
                conn.set_autostart(0)
                return HttpResponseRedirect(request.get_full_path() + '#instancesettings')
            if 'change_settings' in request.POST:
                description = request.POST.get('description', '')
                cur_vcpu_original = vcpu
                cur_mem_original = cur_memory
                vcpu = request.POST.get('vcpu', '')
                cur_vcpu = request.POST.get('cur_vcpu', '')
                memory = request.POST.get('memory', '')
                memory_custom = request.POST.get('memory_custom', '')
                if memory_custom:
                    memory = memory_custom
                cur_memory = request.POST.get('cur_memory', '')
                cur_memory_custom = request.POST.get('cur_memory_custom', '')
                hd_resources_set = request.POST.getlist("ethx")
                if cur_memory_custom:
                    cur_memory = cur_memory_custom
                conn.change_settings(description, cur_memory, cur_memory, cur_vcpu, cur_vcpu, hd_resources_set)

                hd_resources_all = util.load_hd_resources()
                for vf in hd_resources_checked:
                    if vf not in hd_resources_set:
                       hd_resources_all[vf]['used'] = 0 

                for vf in hd_resources_set:
                    hd_resources_all[vf]['used'] = 1

                hd_resources_all["vcpu"] = int(hd_resources_all["vcpu"]) - int(cur_vcpu) + cur_vcpu_original
                hd_resources_all["mem"] = (int(hd_resources_all["mem"]) * 1024 - int(cur_memory)) / 1024 + int(cur_mem_original)/1024
                util.save_hd_resources(hd_resources_all)

                return HttpResponseRedirect(request.get_full_path() + '#instancesettings')
            if 'change_xml' in request.POST:
                xml = request.POST.get('inst_xml', '')
                if xml:
                    conn._defineXML(xml)
                    return HttpResponseRedirect(request.get_full_path() + '#instancexml')
            if 'set_console_passwd' in request.POST:
                if request.POST.get('auto_pass', ''):
                    passwd = ''.join([choice(letters + digits) for i in xrange(12)])
                else:
                    passwd = request.POST.get('console_passwd', '')
                    clear = request.POST.get('clear_pass', False)
                    if clear:
                        passwd = ''
                    if not passwd and not clear:
                        msg = _("Enter the console password or select Generate")
                        errors.append(msg)
                if not errors:
                    if not conn.set_console_passwd(passwd):
                        msg = _("Error setting console password. You should check that your instance have an graphic device.")
                        errors.append(msg)
                    else:
                        return HttpResponseRedirect(request.get_full_path() + '#console_pass')

            if 'set_console_keymap' in request.POST:
                keymap = request.POST.get('console_keymap', '')
                clear = request.POST.get('clear_keymap', False)
                if clear:
                    conn.set_console_keymap('')
                else:
                    conn.set_console_keymap(keymap)
                return HttpResponseRedirect(request.get_full_path() + '#console_keymap')

            if 'set_console_type' in request.POST:
                console_type = request.POST.get('console_type', '')
                conn.set_console_type(console_type)
                return HttpResponseRedirect(request.get_full_path() + '#console_type')

            if 'migrate' in request.POST:
                compute_id = request.POST.get('compute_id', '')
                live = request.POST.get('live_migrate', False)
                unsafe = request.POST.get('unsafe_migrate', False)
                xml_del = request.POST.get('xml_delete', False)
                new_compute = Compute.objects.get(id=compute_id)
                conn_migrate = wvmInstances(new_compute.hostname,
                                            new_compute.login,
                                            new_compute.password,
                                            new_compute.type)
                conn_migrate.moveto(conn, vname, live, unsafe, xml_del)
                conn_migrate.define_move(vname)
                conn_migrate.close()
                return HttpResponseRedirect(reverse('instance', args=[compute_id, vname]))
            if 'delete_snapshot' in request.POST:
                snap_name = request.POST.get('name', '')
                conn.snapshot_delete(snap_name)
                return HttpResponseRedirect(request.get_full_path() + '#istaceshapshosts')
            if 'revert_snapshot' in request.POST:
                snap_name = request.POST.get('name', '')
                conn.snapshot_revert(snap_name)
                msg = _("Successful revert snapshot: ")
                msg += snap_name
                messages.append(msg)
            if 'clone' in request.POST:
                clone_data = {}
                clone_data['name'] = request.POST.get('name', '')

                for post in request.POST:
                    if 'disk' or 'meta' in post:
                        clone_data[post] = request.POST.get(post, '')

                conn.clone_instance(clone_data)
                return HttpResponseRedirect(reverse('instance', args=[host_id, clone_data['name']]))
            if 'add_vf' in request.POST:
                from django.utils.translation import ugettext as _
                count_vf = 0
                for pf,vfs in vf_infos.items():
                    for vf in vfs:
                        count_vf = count_vf+1
                cnt_max = settings.vf_cnt_max
                if count_vf>cnt_max:
                    errors.append(_("One instance has amount max VF is:")+str(cnt_max))
                    return render_to_response('instance.html', locals(), context_instance=RequestContext(request))
                vf_data = request.POST.getlist('interfaces')
                if (len(vf_data)+count_vf)>cnt_max:
                    errors.append(_("One instance has amount max VF is:")+str(cnt_max))
                    return render_to_response('instance.html', locals(), context_instance=RequestContext(request))
                inst_xml = conn.change_nics_settings(True, vf_data)
                vf_infos = util.get_pfvf_map(vname)
                if not vf_infos:
		    vf_infos = {
			"test_pf1":[("vf1",'1.0.21'),('vf2','1.0.22')],
			"test_pf2":[("vf2",'1.0.31'),("vf3",'1.0.32')],
			"test_pf3":[("vf3",'1.0.41'),("vf5",'1.0.42')],
		    }
                
                return HttpResponseRedirect('/instance/%s/%s'%(host_id,vname))
            if 'del_vf' in request.POST:
                del_vf_id = request.POST.get('vf_id', '')
                count_vf = 0
                for pf,vfs in vf_infos.items():
                    for vf in vfs:
                        count_vf = count_vf+1
                if count_vf == 1:
                    errors.append(_("It is the last Vf. Can't delete !"))
                    return render_to_response('instance.html', locals(), context_instance=RequestContext(request))
                inst_xml = conn.change_nics_settings(False, [del_vf_id])
                vf_infos = util.get_pfvf_map(vname)
                is_vf = True
                if not vf_infos:
		    vf_infos = {
			"test_pf1":[("vf1",'1.0.21'),('vf2','1.0.22')],
			"test_pf2":[("vf2",'1.0.31'),("vf3",'1.0.32')],
			"test_pf3":[("vf3",'1.0.41'),("vf5",'1.0.42')],
		    }
                return HttpResponseRedirect('/instance/%s/%s'%(host_id,vname))
        conn.close()

    except libvirtError as err:
        errors.append(err)
    return render_to_response('instance.html', locals(), context_instance=RequestContext(request))
