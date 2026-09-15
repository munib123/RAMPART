from django import forms

from .models import Address, Profile


class ProfileForm(forms.ModelForm):
    """The canonical Django fix for mass assignment: the form declares the writable fields, so
    is_vendor / store_credit can never be set from a request no matter what it contains."""

    class Meta:
        model = Profile
        fields = ["display_name", "bio"]


class AddressForm(forms.ModelForm):
    class Meta:
        model = Address
        fields = ["line1", "line2", "city"]


class AddToCartForm(forms.Form):
    """The canonical Django fix for an unchecked quantity: the bound lives in the form, not
    in the view that does the arithmetic."""
    quantity = forms.IntegerField(min_value=1, max_value=99)
