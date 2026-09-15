from rest_framework import serializers

from .models import Wallet


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ["id", "balance", "currency"]
        read_only_fields = ["balance"]


class WalletSettingsSerializer(serializers.ModelSerializer):
    """The only field a customer may change on their wallet."""

    class Meta:
        model = Wallet
        fields = ["currency"]
