# Copyright 2010 VPAC
#
# This file is part of django_shibboleth.
#
# django_shibboleth is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# django_shibboleth is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with django_shibboleth  If not, see <http://www.gnu.org/licenses/>.

from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.template import loader, RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
from django.conf import settings
from django.contrib import auth

from django_shibboleth.utils import parse_attributes
from django_shibboleth.signals import shib_logon_done


SHIB_USERNAME = getattr(settings, "SHIB_USERNAME", "shared_token")


def render_forbidden(*args, **kwargs):
    httpresponse_kwargs = {'mimetype': kwargs.pop('mimetype', None)}
    return HttpResponseForbidden(loader.render_to_string(*args, **kwargs),
                                 **httpresponse_kwargs)


def shib_login(request, user_model=None):
    redirect_url = request.REQUEST.get('next', settings.LOGIN_REDIRECT_URL)
    if request.user.is_authenticated():
        return HttpResponseRedirect(redirect_url)

    attr, error = parse_attributes(request.META)
    was_redirected = False
    if "next" in request.REQUEST:
        was_redirected = True

    context = {'shib_attrs': attr,
               'was_redirected': was_redirected}
    if error:
        return render_forbidden('shibboleth/attribute_error.html', context,
                                context_instance=RequestContext(request))

    user = authenticate(remote_user=attr[SHIB_USERNAME], shib_meta=attr, user_model=user_model)
    if user:
        login(request, user)
        shib_logon_done.send(sender=shib_login, user=user, shib_attrs=attr, user_model=user_model)
        return HttpResponseRedirect(redirect_url)
    return HttpResponseForbidden("Access Forbidden")


def shib_meta(request):
    meta_data = request.META.items()
    return render_to_response('shibboleth/meta.html',
                              {'meta_data': meta_data},
                              context_instance=RequestContext(request))
