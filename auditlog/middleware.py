import threading
import time
from functools import partial

from django.apps import apps
from django.conf import settings
from django.db.models.signals import pre_save
from django.utils.deprecation import MiddlewareMixin

from auditlog.models import LogEntry

from rest_framework.authentication import TokenAuthentication
from django.utils.functional import SimpleLazyObject
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.middleware import get_user

class RestAuthMiddleware(MiddlewareMixin):

    def __init__(self, get_response):
        self.get_response = get_response

    @staticmethod
    def get_user(request):
        user = get_user(request)
        if user.is_authenticated:
            return user
        token_authentication = TokenAuthentication()
        try:
            user, token = token_authentication.authenticate(request)
        except:
            pass
        return user

    def __call__(self, request):
        request.user = SimpleLazyObject(lambda: self.__class__.get_user(request))
        response = self.get_response(request)
        return response

threadlocal = threading.local()


class AuditlogMiddleware(RestAuthMiddleware):
    """
    Middleware to couple the request's user to log items. This is accomplished by currying the signal receiver with the
    user from the request (or None if the user is not authenticated).
    """

    def process_request(self, request):
        """
        Gets the current user from the request and prepares and connects a signal receiver with the user already
        attached to it.
        """
        # Initialize thread local storage
        threadlocal.auditlog = {
            "signal_duid": (self.__class__, time.time()),
            "remote_addr": request.META.get("REMOTE_ADDR"),
        }

        # In case of proxy, set 'original' address
        if request.META.get("HTTP_X_FORWARDED_FOR"):
            threadlocal.auditlog["remote_addr"] = request.META.get(
                "HTTP_X_FORWARDED_FOR"
            ).split(",")[0]

        # Connect signal for automatic logging
        if hasattr(request, "user"):
            set_actor = partial(
                self.set_actor,
                user=request.user,
                signal_duid=threadlocal.auditlog["signal_duid"],
            )
            pre_save.connect(
                set_actor,
                sender=LogEntry,
                dispatch_uid=threadlocal.auditlog["signal_duid"],
                weak=False,
            )

    def process_response(self, request, response):
        """
        Disconnects the signal receiver to prevent it from staying active.
        """
        if hasattr(threadlocal, "auditlog"):
            pre_save.disconnect(
                sender=LogEntry, dispatch_uid=threadlocal.auditlog["signal_duid"]
            )

        return response

    def process_exception(self, request, exception):
        """
        Disconnects the signal receiver to prevent it from staying active in case of an exception.
        """
        if hasattr(threadlocal, "auditlog"):
            pre_save.disconnect(
                sender=LogEntry, dispatch_uid=threadlocal.auditlog["signal_duid"]
            )

        return None

    @staticmethod
    def set_actor(user, sender, instance, signal_duid, **kwargs):
        """
        Signal receiver with an extra, required 'user' kwarg. This method becomes a real (valid) signal receiver when
        it is curried with the actor.
        """
        if hasattr(threadlocal, "auditlog"):
            if signal_duid != threadlocal.auditlog["signal_duid"]:
                return
            try:
                app_label, model_name = settings.AUTH_USER_MODEL.split(".")
                auth_user_model = apps.get_model(app_label, model_name)
            except ValueError:
                auth_user_model = apps.get_model("auth", "user")
            if (
                sender == LogEntry
                and getattr(user, 'is_authenticated', False)
                and isinstance(user, auth_user_model)
                and instance.actor is None
            ):
                instance.actor = user

            instance.remote_addr = threadlocal.auditlog["remote_addr"]
