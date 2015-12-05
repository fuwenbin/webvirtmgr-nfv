#
# Copyright (C) 2013 Webvirtmgr.
#
import re
import random
import libxml2
import libvirt
import json
import os
import commands
import socket,struct
import xml.etree.ElementTree as Etree

def addressInNetwork(ip,net):
   "Is an address in a network"
   ipaddr = struct.unpack('L',socket.inet_aton(ip))[0]
   netaddr,bits = net.split('/')
   netmask = struct.unpack('L',socket.inet_aton(netaddr))[0] & ((2L<<int(bits)-1) - 1)
   return ipaddr & netmask == netmask

def is_kvm_available(xml):
    capabilites = re.search('kvm', xml)
    if capabilites:
        return True
    else:
        return False


def randomMAC():
    """Generate a random MAC address."""
    # qemu MAC
    oui = [0x52, 0x54, 0x00]

    mac = oui + [random.randint(0x00, 0xff),
                 random.randint(0x00, 0xff),
                 random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def randomUUID():
    """Generate a random UUID."""

    u = [random.randint(0, 255) for dummy in range(0, 16)]
    return "-".join(["%02x" * 4, "%02x" * 2, "%02x" * 2, "%02x" * 2, "%02x" * 6]) % tuple(u)


def get_max_vcpus(conn, type=None):
    """@param conn: libvirt connection to poll for max possible vcpus
       @type type: optional guest type (kvm, etc.)"""
    if type is None:
        type = conn.getType()
    try:
        m = conn.getMaxVcpus(type.lower())
    except libvirt.libvirtError:
        m = 32
    return m


def xml_escape(str):
    """Replaces chars ' " < > & with xml safe counterparts"""
    if str is None:
        return None

    str = str.replace("&", "&amp;")
    str = str.replace("'", "&apos;")
    str = str.replace("\"", "&quot;")
    str = str.replace("<", "&lt;")
    str = str.replace(">", "&gt;")
    return str


def compareMAC(p, q):
    """Compare two MAC addresses"""
    pa = p.split(":")
    qa = q.split(":")

    if len(pa) != len(qa):
        if p > q:
            return 1
        else:
            return -1

    for i in xrange(len(pa)):
        n = int(pa[i], 0x10) - int(qa[i], 0x10)
        if n > 0:
            return 1
        elif n < 0:
            return -1
    return 0


def get_xml_path(xml, path=None, func=None):
    """
    Return the content from the passed xml xpath, or return the result
    of a passed function (receives xpathContext as its only arg)
    """
    doc = None
    ctx = None
    result = None

    try:
        doc = libxml2.parseDoc(xml)
        ctx = doc.xpathNewContext()

        if path:
            ret = ctx.xpathEval(path)
            if ret is not None:
                if type(ret) == list:
                    if len(ret) >= 1:
                        result = ret[0].content
                else:
                    result = ret

        elif func:
            result = func(ctx)

        else:
            raise ValueError("'path' or 'func' is required.")
    finally:
        if doc:
            doc.freeDoc()
        if ctx:
            ctx.xpathFreeContext()
    return result


def pretty_mem(val):
    val = int(val)
    if val > (10 * 1024 * 1024):
        return "%2.2f GB" % (val / (1024.0 * 1024.0))
    else:
        return "%2.0f MB" % (val / 1024.0)


def pretty_bytes(val):
    val = int(val)
    if val > (1024 * 1024 * 1024):
        return "%2.2f GB" % (val / (1024.0 * 1024.0 * 1024.0))
    else:
        return "%2.2f MB" % (val / (1024.0 * 1024.0))

def get_total_vcpu_mem():
    '''
    get host vcpu and mem. 
    '''
    get_vcpu_cmd = "cat /proc/cpuinfo | grep 'model name' | grep -v grep | wc -l"
    (status, vcpu) = commands.getstatusoutput(get_vcpu_cmd)
    get_mem_cmd = "cat /proc/meminfo | grep MemTotal | grep -v grep | awk '{ print $2}'"
    (status, mem) = commands.getstatusoutput(get_mem_cmd)

    return vcpu, mem

def get_hd_resources_conf():
    '''
    return path of configfile for hardware resources.
    '''
    root_path = os.path.join(os.path.dirname(__file__), "../")

    filename = root_path+"/resource_mgr.conf"

    return filename

def get_all_vf():
    '''
    Get all vfs in the host. 'pcid': {'pname': '1', 'vname' : '2', 'used': 0}
    '''
    vfs = {}
    get_nics_cmd="ls /sys/class/net"
    (status, output) = commands.getstatusoutput(get_nics_cmd)
    if status != 0:
        return vfs

    nics = [ nic for nic in output.split('\n')]
    for pfname in nics:
        path_check = "/sys/class/net/" + pfname +"/device/"
        if not os.path.exists(path_check + "virtfn0"):
            continue

        get_nic_cmd = "ls -l " + path_check + "virtfn* | awk '{ print $11}' | sed  -e 's/\///g' -e 's/..0000://' "
        (status, output) = commands.getstatusoutput(get_nic_cmd)
        if status == 0 and len(output) > 0:
            i=0
            for vf in output.split('\n'):
                vfs.setdefault(vf ,{'pname':pfname, 'vname':'vport%d' % i, 'used': 0})
                i=i+1

    return vfs

def create_hd_resources():
    '''
    Init the file saving vfs, using state is 0; saving left vcpu and mem(G).
    '''
    hd_resources = get_all_vf()
    vcpu, mem = get_total_vcpu_mem()
    hd_resources["mem"] = int(round(float(mem)/1048576))
    hd_resources["vcpu"] = vcpu
    file_object = open(get_hd_resources_conf(), 'w')
    json.dump(hd_resources, file_object)
    file_object.close()
    
    return hd_resources

def load_hd_resources():
    '''
    load hardware resources.
    '''
    temp_hd_resources = None
    if os.path.exists(get_hd_resources_conf()):
        file_object = open(get_hd_resources_conf(),'r')
        temp_hd_resources = json.load(file_object)
        file_object.close()
    else:
        temp_hd_resources = create_hd_resources()
    return temp_hd_resources

def save_hd_resources(hd_resources):
    '''
    overwrite hardware resources to file
    '''
    file_object = open(get_hd_resources_conf(), 'w')
    json.dump(hd_resources, file_object)
    file_object.close()

def filter_hd_resources(hd_resources):
    '''
    get unused vfs, mem and vcpu. 
    '''
    for key in hd_resources.keys():
        if key == 'vcpu' or key == 'mem' or hd_resources[key]['used'] != 0:
            del(hd_resources[key])

    return hd_resources

def update_vfs_fro_vm(vm_vfs_info):
    '''
    Set used vfs to local file.
    '''
    updated_flag = True
    hd_resources = load_hd_resources()
    for vm in vm_vfs_info.keys():
        for vf in vm_vfs_info[vm]:
            if vf not in hd_resources or hd_resources[vf]['used'] == 1:
                updated_flag = False
                break
            else:
                hd_resources[vf]['used'] = 1

    if updated_flag:
        save_hd_resources(hd_resources)

    return updated_flag

def del_vfs_fro_vm(vfs):
    hd_resources = load_hd_resources()
    for vf in vfs:
        if vf in hd_resources or hd_resources[vf]['used'] == 1:
            hd_resources[vf]['used'] = 0
    save_hd_resources(hd_resources)

def add_vfs_for_vm(vfs):
    hd_resources = load_hd_resources()
    for vf in vfs:
        if vf in hd_resources or hd_resources[vf]['used'] == 0:
            hd_resources[vf]['used'] = 1
    save_hd_resources(hd_resources)

def get_free_vfs():
    '''
    Get free vfs.def 
    '''
    vfs = []
    vfs_pf = {}
    get_nics_cmd="ls /sys/class/net"
    (status, output) = commands.getstatusoutput(get_nics_cmd)
    if status != 0:
        return tuple(vfs_pf)

    hd_resources = load_hd_resources()
    nics = [ nic for nic in output.split('\n')]
    for pfname in nics:
        path_check = "/sys/class/net/" + pfname +"/device/"
        if not os.path.exists(path_check + "virtfn0"):
            continue

        get_nic_cmd = "ls -l " + path_check + "virtfn* | awk '{ print $11}' | sed  -e 's/\///g' -e 's/..0000://' "
        (status, output) = commands.getstatusoutput(get_nic_cmd)
        if status == 0 and len(output) > 0:
            vfs = [ vf for vf in output.split('\n')]
            vfs_copy = {}

            for vf in vfs:
                if hd_resources.has_key(vf) and hd_resources[vf]['used'] != 1:
                    vfs_copy[hd_resources[vf]['vname']]=vf
                    
            if len(vfs_copy) == 0:
                continue
            vfs_pf[pfname] = vfs_copy


    return vfs_pf

def get_network_config_file():
    return '/etc/network/interfaces'

def get_data_from_file():
    interface_file = open(get_network_config_file())
    context_info = interface_file.read()
    interface_file.close()
    return context_info

def write_data_to_file(data):
    interface_file = open(get_network_config_file(), "wt")
    interface_file.write(data)
    interface_file.close()

def replace_config(context_info, ip, getway):
    new_config = ""
    start_flag = -1
    array_nics = context_info.split("auto ")
    for data in array_nics:
        start_flag = start_flag + 1
        if start_flag != 0:
            new_config =  new_config + "auto "
        if data.startswith("br0"):
            for item in data.split("\n"):
                if item.find("#") != -1:
                    item = item[:item.find("#")]
                if item.find("address") != -1:
                    new_config =  new_config + "address %s\n" % (ip.split("/")[0])
                elif item.find("gateway") != -1:
                    new_config =  new_config + "netmask %s\n" % (get_netmask(ip.split("/")[1]))
                elif item.find("netmask") != -1:
                    new_config =  new_config + "gateway %s\n" % (getway)
                else:
                    new_config =  new_config + item + "\n"
        else:
            new_config = new_config + data

    write_data_to_file(new_config)

def get_config(context_info):
    gate_way = ""
    net_mask = ""
    new_config = ""
    array_nics = context_info.split("auto ")
    for data in array_nics:
        if data.startswith("br0"):
            for item in data.split("\n"):
                if item.find("#") != -1:
                    item = item[:item.find("#")]
                if item.find("address") != -1:
                    ip_addr = item.split()[1].strip()
                elif item.find("gateway") != -1:
                    gate_way = item.split()[1].strip()
                elif item.find("netmask") != -1:
                    net_mask = item.split()[1].strip()

    return (ip_addr+ "/" + get_prefix(net_mask),gate_way)

def get_netmask(prefix):
    net_map = { "1":"128.0.0.0", "2":"192.0.0.0","3":"224.0.0.0","4":"240.0.0.0","5":"248.0.0.0",
                "6":"252.0.0.0","7":"254.0.0.0","8":"255.0.0.0","9":"255.128.0.0","10":"255.192.0.0",
                "11":"255.224.0.0","12":"255.240.0.0","13":"255.248.0.0","14":"255.252.0.0",
                "15":"255.254.0.0","16":"255.255.0.0","17":"255.255.128.0","18":"255.255.192.0",
                "19":"255.255.224.0","20":"255.255.240.0","21":"255.255.248.0","22":"255.255.252.0",
                "23":"255.255.254.0","24":"255.255.255.0","25":"255.255.255.128","26":"255.255.255.192",
                "27":"255.255.255.224","28":"255.255.255.240","29":"255.255.255.248","30":"255.255.255.252",
                "31":"255.255.255.254","32":"255.255.255.255" }
    return net_map[prefix]

def get_prefix(netmask):
    net_map={"128.0.0.0":"1" ,"192.0.0.0":"2" ,"224.0.0.0":"3" ,"240.0.0.0":"4" ,"248.0.0.0":"5" ,
             "252.0.0.0":"6" ,"254.0.0.0":"7" ,"255.0.0.0":"8" ,"255.128.0.0":"9" ,"255.192.0.0":"10" ,
             "255.224.0.0":"11" ,"255.240.0.0":"12" ,"255.248.0.0":"13" ,"255.252.0.0":"14" ,
             "255.254.0.0":"15" ,"255.255.0.0":"16" ,"255.255.128.0":"17" ,"255.255.192.0":"18" ,
             "255.255.224.0":"19" ,"255.255.240.0":"20" ,"255.255.248.0":"21" ,"255.255.252.0":"22" ,
             "255.255.254.0":"23" ,"255.255.255.0":"24" ,"255.255.255.128":"25" ,"255.255.255.192":"26" ,
             "255.255.255.224":"27" ,"255.255.255.240":"28" ,"255.255.255.248":"29" ,"255.255.255.252":"30" ,
             "255.255.255.254":"31" ,"255.255.255.255":"32" }
    return net_map[netmask]


import socket,struct

def makeMask(n):
    "return a mask of n bits as a long integer"
    return (2L<<n-1) - 1

def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('I',socket.inet_aton(ip))[0]

def networkMask(ip,bits):
    "Convert a network address to a long integer"
    return dottedQuadToNum(ip) & makeMask(bits)

def addressInNetwork(ip,net):
   "Is an address in a network"
   return ip & net == net

def reload_network(src_ip, dst_ip):
    '''
    reload_network. 
    '''
    cmd = "ifdown --exclude=lo -a && ifup --exclude=lo -a"
    commands.getstatusoutput(cmd)
    
    cmd = "sed -i '$s/" + src_ip + "/" + dst_ip + "/' /etc/init.d/set_pfup_vfmac"
    commands.getstatusoutput(cmd)

def get_pfvf_map(vmname):
    
    get_pf_cmd= "cat /etc/libvirt/qemu/" + vmname + ".xml | grep -E 'description|address domain' "
    (status, output) = commands.getstatusoutput(get_pf_cmd)
    if status != 0:
        return dict()

    hd_resources = load_hd_resources()

    i = 0
    pfnames = {}
    if_prefix = "10GE"
    if output.find("<description>ver3") != -1:
        i = 1

    for pf_item in output.split('\n'):
        pf_obj = Etree.fromstring(pf_item)
        if pf_obj.get('bus') is None:
            continue
        pf_pci = pf_obj.get('bus') + ":" + pf_obj.get('slot')+ "."  + pf_obj.get('function')
        pf_pci = pf_pci.replace("0x", "")
        i = i + 1

        pf_name = hd_resources[pf_pci]['pname']
        if pf_name.startswith("GE"):
            if_prefix = "GE"
        else:
            if_prefix = "10GE"

        vf_info=(if_prefix + "1." + str(i), pf_pci)
        if pfnames.has_key(pf_name):
            pfnames[pf_name].append(vf_info)
        else:
            pfnames.setdefault(pf_name, [vf_info])

    return pfnames

def get_totalmac_setmac():
    total_mac_cnt = 0
    valid_mac_cnt = 0

    total_mac_cmd = "ip link show | grep vf | wc -l"
    (status, output) = commands.getstatusoutput(total_mac_cmd)
    if status != 0 or int(output) == 0:
        return (total_mac_cnt, valid_mac_cnt)

    total_mac_cnt = int(output)
    kvm_mac_cmd= """ip link show | grep vf | grep "52:54:00" | wc -l"""
    (status, output) = commands.getstatusoutput(kvm_mac_cmd)
    if status == 0:
        valid_mac_cnt = int(output)

    return total_mac_cnt, total_mac_cnt - valid_mac_cnt


def set_mac_for_vf():
    config_mac_cmd= "/var/www/utils/config_mac"
    commands.getstatusoutput(config_mac_cmd)

    return get_totalmac_setmac()

