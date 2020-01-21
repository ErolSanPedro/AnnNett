from django.db import models
from django.utils.timezone import now
from datetime import datetime

# Create your models here.

class Blacklist(models.Model):
	id = models.AutoField(primary_key=True)
	ipaddress = models.CharField(max_length = 45, null=True, blank=True)
	domain = models.CharField(max_length = 500, null=True, blank=True, default="")
	port = models.IntegerField(null = True, blank=True, default = 80)

	def __str__(self):

		if self.ipaddress:
			return self.ipaddress
		elif self.domain:
			return self.domain
		else:
			return self.id	

class Penalty(models.Model):
	id = models.AutoField(primary_key=True)
	id_blacklist = models.ForeignKey(Blacklist, on_delete=models.CASCADE)
	lastaccessed = models.DateTimeField(default= now)
	penaltycount = models.IntegerField(null = True, default = 0)
	rulenum = models.IntegerField(null = True, default = 0)
	status = models.CharField(max_length = 45)

	def __str__(self):
		return self.ipaddress

class Audit(models.Model):
	id = models.AutoField(primary_key=True)
	#penalty_id = models.ForeignKey(Penalty, on_delete=models.CASCADE)
	sourceip = models.CharField( max_length = 45)
	macaddress = models.CharField(max_length = 45)
	time = models.DateTimeField(null = True)

	def __str__(self):
		return self.sourceip