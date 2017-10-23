from django.conf.urls import url
from . import views

urlpatterns = [
	url(r'^$', views.op),
	url(r'^login$', views.login),
	url(r'^login/process$', views.loginprocess),
	url(r'^registration$', views.register),
	url(r'^registration/process$', views.registerprocess),
	url(r'^addalert$', views.addalert),
	url(r'^display$', views.display),     #####crime ID????
	url(r'^addalert/process$', views.addalertprocess),
	url(r'^submitform$', views.formprocess),
	url(r'^crimes$', views.index),



	url(r'^$', views.index),

]
