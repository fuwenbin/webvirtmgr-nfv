#
# Copyright (C) 2013 Webvirtmgr.
#
import string
from vrtManager import util
from vrtManager.connection import wvmConnect

from webvirtmgr.settings import QEMU_CONSOLE_DEFAULT_TYPE


def get_rbd_storage_data(stg):
    xml = stg.XMLDesc(0)
    ceph_user = util.get_xml_path(xml, "/pool/source/auth/@username")
    ceph_host = util.get_xml_path(xml, "/pool/source/host/@name")
    secrt_uuid = util.get_xml_path(xml, "/pool/source/auth/secret/@uuid")
    return ceph_user, secrt_uuid, ceph_host


class wvmCreate(wvmConnect):
    def get_storages_images(self):
        """
        Function return all images on all storages
        """
        images = []
        storages = self.get_storages()
        for storage in storages:
            stg = self.get_storage(storage)
            try:
                stg.refresh(0)
            except:
                pass
            for img in stg.listVolumes():
                if img.endswith('.iso'):
                    pass
                else:
                    images.append(img)
        return images

    def get_os_type(self):
        """Get guest capabilities"""
        return util.get_xml_path(self.get_cap_xml(), "/capabilities/guest/os_type")

    def get_host_arch(self):
        """Get guest capabilities"""
        return util.get_xml_path(self.get_cap_xml(), "/capabilities/host/cpu/arch")

    def create_volume(self, storage, name, size, format='qcow2', metadata=False):
        size = int(size) * 1073741824
        stg = self.get_storage(storage)
        storage_type = util.get_xml_path(stg.XMLDesc(0), "/pool/@type")
        if storage_type == 'dir':
            name += '.img'
            alloc = 0
        else:
            alloc = size
            metadata = False
        xml = """
            <volume>
                <name>%s</name>
                <capacity>%s</capacity>
                <allocation>%s</allocation>
                <target>
                    <format type='%s'/>
                </target>
            </volume>""" % (name, size, alloc, format)
        stg.createXML(xml, metadata)
        try:
            stg.refresh(0)
        except:
            pass
        vol = stg.storageVolLookupByName(name)
        return vol.path()

    def get_volume_type(self, path):
        vol = self.get_volume_by_path(path)
        vol_type = util.get_xml_path(vol.XMLDesc(0), "/volume/target/format/@type")
        if vol_type == 'unknown':
            return 'raw'
        if vol_type:
            return vol_type
        else:
            return 'raw'

    def get_volume_path(self, volume):
        storages = self.get_storages()
        for storage in storages:
            stg = self.get_storage(storage)
            if stg.info()[0] != 0:
                stg.refresh(0)
                for img in stg.listVolumes():
                    if img == volume:
                        vol = stg.storageVolLookupByName(img)
                        return vol.path()

    def get_storage_by_vol_path(self, vol_path):
        vol = self.get_volume_by_path(vol_path)
        return vol.storagePoolLookupByVolume()

    def clone_from_template(self, clone, template, metadata=False):
        vol = self.get_volume_by_path(template)
        #stg = vol.storagePoolLookupByVolume() # not using template's dir to save vm images.
        stg = self.get_storage("VmImages")
        storage_type = util.get_xml_path(stg.XMLDesc(0), "/pool/@type")
        format = util.get_xml_path(vol.XMLDesc(0), "/volume/target/format/@type")
        if storage_type == 'dir':
            clone += '.img'
        else:
            metadata = False
        xml = """
            <volume>
                <name>%s</name>
                <capacity>0</capacity>
                <allocation>0</allocation>
                <target>
                    <format type='%s'/>
                </target>
            </volume>""" % (clone, format)
        stg.createXMLFrom(xml, vol, metadata)
        clone_vol = stg.storageVolLookupByName(clone)
        return clone_vol.path()

    def _defineXML(self, xml):
        self.wvm.defineXML(xml)

    def delete_volume(self, path):
        vol = self.get_volume_by_path(path)
        vol.delete()

    def create_instance(self, name, memory, vcpu, uuid, images, networks, host_model=False, virtio=True, template_ver3=True):
        """
        Create VM function
        """
        memory = int(memory) * 1024

        if self.is_kvm_supported():
            hypervisor_type = 'kvm'
        else:
            hypervisor_type = 'qemu'

        vm_template = "ver4"
        if template_ver3:
            vm_template = "ver3"

        xml = u"""
                <domain type='%s'>
                  <name>%s</name>
                  <description>%s</description>
                  <uuid>%s</uuid>
                  <memory unit='KiB'>%s</memory>
                  <vcpu>%s</vcpu>""" % (hypervisor_type, name, vm_template, uuid, memory, vcpu)
        if host_model:
            xml += """<cpu mode='host-model'/>"""
        xml +=u"""<os>
                    <type arch='%s'>%s</type>
                    <boot dev='hd'/>
                    <boot dev='cdrom'/>
                    <bootmenu enable='yes'/>
                  </os>""" % (self.get_host_arch(), self.get_os_type())
        xml += u"""<features>
                    <acpi/><apic/><pae/>
                  </features>
                  <clock offset="utc"/>
                  <on_poweroff>destroy</on_poweroff>
                  <on_reboot>restart</on_reboot>
                  <on_crash>restart</on_crash>
                  <devices>"""

        disk_letters = list(string.lowercase)
        for image, img_type in images.items():
            stg = self.get_storage_by_vol_path(image)
            stg_type = util.get_xml_path(stg.XMLDesc(0), "/pool/@type")

            if stg_type == 'rbd':
                ceph_user, secrt_uuid, ceph_host = get_rbd_storage_data(stg)
                xml += u"""<disk type='network' device='disk'>
                            <driver name='qemu' type='%s'/>
                            <auth username='%s'>
                                <secret type='ceph' uuid='%s'/>
                            </auth>
                            <source protocol='rbd' name='%s'>
                                <host name='%s' port='6789'/>
                            </source>""" % (img_type, ceph_user, secrt_uuid, image, ceph_host)
            else:
                xml += u"""<disk type='file' device='disk'>
                            <driver name='qemu' type='%s'/>
                            <source file='%s'/>""" % (img_type, image)

            if virtio:
                xml += u"""<target dev='vd%s' bus='virtio'/>""" % (disk_letters.pop(0),)
            else:
                xml += u"""<target dev='sd%s' bus='ide'/>""" % (disk_letters.pop(0),)
            xml += u"""</disk>"""

        xml += u"""  <disk type='file' device='cdrom'>
                      <driver name='qemu' type='raw'/>
                      <source file=''/>
                      <target dev='hda' bus='ide'/>
                      <readonly/>
                      <address type='drive' controller='0' bus='1' target='0' unit='1'/>
                    </disk>"""

        xml += u"""  <interface type='bridge'>
                      <mac address='%s'/>
                      <source bridge='br0'/>
                      <model type='e1000'/>
                      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
                    </interface>""" % util.randomMAC()
                      
        hd_resources = util.load_hd_resources()

        slot_index = 6
        for net in networks:
            slot_index = slot_index + 1
            xml += u"""<hostdev mode='subsystem' type='pci' managed='yes'><source>"""
            bus = net.split(":")[0]
            slot = net.split(":")[1].split(".")[0]
            func = net.split(":")[1].split(".")[1]
            hd_resources[net]['used'] = 1 
            xml += u"""<address domain='0x0000' bus='0x%s' slot='0x%s' function='0x%s'/></source>""" % (bus, slot, func)
            xml += u"""<address type='pci' domain='0x0000' bus='0x00' slot='0x%02x' function='0x0'/>""" % slot_index
            xml += u"""</hostdev>"""

        hd_resources["mem"] = int(hd_resources["mem"]) - memory / (1024*1024)
        hd_resources["vcpu"] = int(hd_resources["vcpu"]) - vcpu
        util.save_hd_resources(hd_resources)

        xml += u"""  <input type='mouse' bus='ps2'/>
                    <input type='tablet' bus='usb'/>
                    <graphics type='%s' port='-1' autoport='yes' listen='0.0.0.0'>
                      <listen type='address' address='0.0.0.0'/>
                    </graphics>
                    <console type='pty'/>
                    <video>
                      <model type='cirrus'/>
                    </video>
                    <memballoon model='virtio'/>
                  </devices>
                </domain>""" % QEMU_CONSOLE_DEFAULT_TYPE
        self._defineXML(xml)
