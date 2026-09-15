"""Wallet API. Ownership is meant to come from get_queryset() - which only protects the methods
that go through it."""
from decimal import Decimal

from django.db import transaction
from django.db.models import F
from django.shortcuts import get_object_or_404
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Wallet
from .serializers import WalletSerializer, WalletSettingsSerializer


class WalletViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WalletSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Wallet.objects.filter(owner=self.request.user)

    @action(detail=True, methods=["post"])
    def transfer(self, request, pk=None):
        """Moves money out of ANY wallet: the source is looked up by pk, not through get_queryset()."""
        source = Wallet.objects.get(pk=pk)
        target = Wallet.objects.get(pk=request.data["to"])
        amount = Decimal(request.data["amount"])
        with transaction.atomic():
            source.balance = source.balance - amount
            target.balance = target.balance + amount
            source.save()
            target.save()
        return Response({"from": source.pk, "to": target.pk, "amount": str(amount)})

    @action(detail=True, methods=["get"])
    def statement(self, request, pk=None):
        """Safe: get_object() filters through get_queryset(), so a foreign pk is a 404."""
        wallet = self.get_object()
        payouts = wallet.payouts.order_by("-requested_at")[:50]
        return Response({"balance": str(wallet.balance),
                         "payouts": [{"amount": str(p.amount), "at": p.requested_at} for p in payouts]})

    @action(detail=True, methods=["post"])
    def close(self, request, pk=None):
        """Safe: the lookup itself is scoped to the owner."""
        wallet = get_object_or_404(Wallet, pk=pk, owner=request.user)
        Wallet.objects.filter(pk=wallet.pk).update(frozen=True)
        return Response({"closed": wallet.pk})

    @action(detail=True, methods=["patch"])
    def settings(self, request, pk=None):
        """Mass assignment on an owned wallet: balance and credit_limit are one key away."""
        wallet = get_object_or_404(Wallet, pk=pk, owner=request.user)
        for key, value in request.data.items():
            setattr(wallet, key, value)
        wallet.save()
        return Response(WalletSerializer(wallet).data)

    @action(detail=True, methods=["patch"])
    def settings_safe(self, request, pk=None):
        """The documented fix: a serializer whose Meta.fields (serializers.py) is the allow-list."""
        wallet = get_object_or_404(Wallet, pk=pk, owner=request.user)
        serializer = WalletSettingsSerializer(wallet, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(WalletSerializer(wallet).data)
