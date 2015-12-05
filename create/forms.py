import re

from django import forms
from django.utils.translation import ugettext_lazy as _

from create.models import Flavor


class FlavorAddForm(forms.Form):
    label = forms.CharField(label="Name",
                            error_messages={'required': _('No flavor name has been entered')},
                            max_length=20)
    cur_vcpu = forms.IntegerField(label="VCPU",
                              error_messages={'required': _('No VCPU has been entered')}, )
    disk = forms.IntegerField(label="HDD",
                              error_messages={'required': _('No HDD image has been entered')}, )
    cur_memory = forms.IntegerField(label="RAM",
                                error_messages={'required': _('No RAM size has been entered')}, )

    def clean_name(self):
        label = self.cleaned_data['label']
        have_symbol = re.match('^[a-zA-Z0-9._-]+$', label)
        if not have_symbol:
            raise forms.ValidationError(_('The flavor name must not contain any special characters'))
        elif len(label) > 20:
            raise forms.ValidationError(_('The flavor name must not exceed 20 characters'))
        try:
            Flavor.objects.get(label=label)
        except Flavor.DoesNotExist:
            return label
        raise forms.ValidationError(_('Flavor name is already use'))


class NewVMForm(forms.Form):
    name = forms.CharField(error_messages={'required': _('No Virtual Machine name has been entered')},
                           max_length=20)
    cur_vcpu = forms.IntegerField(error_messages={'required': _('No VCPU has been entered')})
    disk = forms.IntegerField(required=False)
    cur_memory = forms.IntegerField(error_messages={'required': _('No RAM size has been entered')})
    storage = forms.CharField(max_length=20, required=False)
    template = forms.CharField(required=False)
    images = forms.CharField(required=False)
    hdd_size = forms.IntegerField(required=False)

    def clean_name(self):
        name = self.cleaned_data['name']
        have_symbol = re.match(ur'^[a-zA-Z0-9\u4e00-\u9fa5._-]+$', name)
        if not have_symbol:
            raise forms.ValidationError(_('The name of the virtual machine must not contain any special characters'))
        elif len(name) > 20:
            raise forms.ValidationError(_('The name of the virtual machine must not exceed 20 characters'))
        return name
