from rest_framework import permissions


class IsOwner(permissions.BasePermission):
    """Object-level permission: only the owner (Order.user / OrderNote.author) may touch it.
    DRF evaluates this ONLY when a view calls self.get_object(); a method that fetches the row
    itself with Model.objects.get() never reaches has_object_permission()."""

    def has_object_permission(self, request, view, obj):
        owner_id = getattr(obj, "user_id", None) or getattr(obj, "author_id", None)
        return owner_id == request.user.id
