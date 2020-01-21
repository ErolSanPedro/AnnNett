from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
	path('', views.index, name='indexSB'),
	path('settings/', views.settings, name='settings'),
	path('settings/updateconf', views.updateconf, name='updateconf'),
	path('updateBlacklistTable', views.updateBlacklistTable, name='updateBlacklistTable'),
	path('updatePenaltyTable', views.updatePenaltyTable, name='updatePenaltyTable'),	
	path('updateAuditTable', views.updateAuditTable, name='updateAuditTable'),
	#path('blacklist/', views.BlacklistListView.as_view(), name='blacklist'),
	path('admin/', admin.site.urls, name='admins'),
]