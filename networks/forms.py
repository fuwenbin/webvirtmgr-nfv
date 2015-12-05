from django import forms
from django.utils.translation import ugettext_lazy as _
import re
from netaddr import IPNetwork
from vrtManager import util


class AddNetPool(forms.Form):
    gateway = forms.CharField(error_messages={'required': _('No gateway has been entered')},
                           max_length=15)
    ipaddr = forms.CharField(error_messages={'required': _('No ipaddr has been entered')},
                             max_length=18)
    #forward = forms.CharField(max_length=100)
    #dhcp = forms.BooleanField(required=False)
    #fixed = forms.BooleanField(required=False)
    #bridge_name = forms.CharField(max_length=20, required=False)
    #openvswitch = forms.BooleanField(required=False)

    def clean_name(self):
        gateway = self.cleaned_data['gateway']
        have_symbol = re.match('^[0-9.]+$', gateway)
        if not have_symbol:
            raise forms.ValidationError(_('The gateway must not contain any special characters'))
        elif len(gateway) > 15:
            raise forms.ValidationError(_('The gateway must not exceed 15 characters'))
        return gateway

    def clean_subnet(self):
        ipaddr = self.cleaned_data['ipaddr']
        gateway = self.cleaned_data['gateway']
        have_symbol = re.match('^[0-9./]+$', ipaddr)
        if not have_symbol:
            raise forms.ValidationError(_('The ipaddr must not contain any special characters'))
        elif len(subnet) > 18:
            raise forms.ValidationError(_('The ipaddr must not exceed 18 characters'))
        elif not util.addressInNetwork(util.dottedQuadToNum(gateway), util.networkMask(str(IPNetwork(ipaddr).network), int(ipaddr.split("/")[1]))):
            raise forms.ValidationError(_('getway setting error'))
        return ipaddr

    def clean_bridge_name(self):
        bridge_name = self.cleaned_data['bridge_name']
        if self.cleaned_data['forward'] == 'bridge':
            have_symbol = re.match('^[a-zA-Z0-9\.\_\:\-]+$', bridge_name)
            if not have_symbol:
                raise forms.ValidationError(_('The pool bridge name must not contain any special characters'))
            elif len(bridge_name) > 20:
                raise forms.ValidationError(_('The pool bridge name must not exceed 20 characters'))
            return bridge_name
