"""DRF endpoints. The permission model lives on the CLASS (permission_classes) and in
permissions.py - the guard is configuration, not a statement in the method body. That is the
case the plan flags as 'guard-as-configuration': a per-method token search cannot see it, and
DRF itself only honours it when the method goes through self.get_object().
"""
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Order, OrderNote
from .permissions import IsOwner
from .serializers import OrderNoteSerializer, OrderSerializer


class OrderViewSet(viewsets.ReadOnlyModelViewSet):
    """Listing and retrieval are scoped by get_queryset(); the custom actions are not all so careful."""
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)

    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        """IsAuthenticated only proves login. Any user can cancel any order by id."""
        order = Order.objects.get(pk=pk)
        order.status = "cancelled"
        order.save()
        return Response({"status": order.status})

    @action(detail=True, methods=["get"])
    def receipt(self, request, pk=None):
        """The documented fix for a custom action: run the object permissions explicitly."""
        order = get_object_or_404(Order, pk=pk)
        self.check_object_permissions(request, order)
        return Response({"id": order.pk, "total": str(order.total), "status": order.status})


class OrderNoteViewSet(viewsets.ModelViewSet):
    """Object-level ownership comes from the class attribute below. DRF runs
    IsOwner.has_object_permission() inside self.get_object() - and nowhere else."""
    serializer_class = OrderNoteSerializer
    permission_classes = [IsAuthenticated, IsOwner]
    queryset = OrderNote.objects.all()

    def retrieve(self, request, pk=None):
        """Safe: get_object() applies the queryset AND the object permissions. Nothing in this
        body names ownership; the guard is the class attribute plus the framework call."""
        note = self.get_object()
        return Response(OrderNoteSerializer(note).data)

    @action(detail=True, methods=["get"])
    def history(self, request, pk=None):
        """Looks protected - IsOwner is right there on the class - but Model.objects.get()
        bypasses get_object(), so has_object_permission() never runs. Any user, any note."""
        note = OrderNote.objects.get(pk=pk)
        versions = note.versions.order_by("-created_at") if hasattr(note, "versions") else []
        return Response({"id": note.pk, "body": note.body, "versions": list(versions)})

    def partial_update(self, request, pk=None):
        note = self.get_object()
        serializer = OrderNoteSerializer(note, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
