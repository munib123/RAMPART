from django import forms

from .models import Ticket


class TicketForm(forms.ModelForm):
    """A customer may edit the subject and body of their ticket - nothing else."""

    class Meta:
        model = Ticket
        fields = ["subject", "body"]


class RefundForm(forms.Form):
    """The returned quantity is bounded here, by the line's quantity, not in the view."""
    qty = forms.IntegerField(min_value=1)

    def __init__(self, *args, max_qty=None, **kwargs):
        super().__init__(*args, **kwargs)
        if max_qty is not None:
            self.fields["qty"].max_value = max_qty
