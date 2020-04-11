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

		# if self.ipaddress:
		# 	return self.ipaddress
		# elif self.domain:
		# 	return self.domain
		# else:
		return str(self.id)

class Penalty(models.Model):
	id = models.AutoField(primary_key=True)
	id_blacklist = models.ForeignKey(Blacklist, on_delete=models.CASCADE)
	lastaccessed = models.DateTimeField(default= now)
	penaltycount = models.IntegerField(null = True, default = 0)
	rulenum = models.IntegerField(null = True, default = 0)
	status = models.CharField(max_length = 45)

	def __int__(self):
		return self.id

class Audit(models.Model):
	id = models.AutoField(primary_key=True)
	#penalty_id = models.ForeignKey(Penalty, on_delete=models.CASCADE)
	sourceip = models.CharField( max_length = 45)
	macaddress = models.CharField(max_length = 45)
	time = models.DateTimeField(null = True)

	def __str__(self):
		return self.sourceip


# class PenaltyInfo(object):
# 	def __init__(self, id, ipaddress, lastaccessed, penaltycount, rulenum, status):
# 		super (PenaltyInfo, self).__init__()
# 		self.id = id
# 		self.ipaddress = ipaddress		  
# 		self.lastaccessed = lastaccessed		
# 		self.penaltycount = penaltycount    		
# 		self.rulenum = rulenum      		
# 		self.status = status      
# 		self.ipaddress = ipaddress	
		


# class PenaltyManager(models.Manager):
# 	# =============================================== ADMIN DASHBOARD ===================================================
# 	# Displays Penalty DB with Blacklist DB details (domain)
# 	def displayPenaltyDB():
# 		arr = [] #set()
# 		cur = conn.cursor()
# 		cur.execute("select main_penalty.id, ipaddress, lastaccessed, penaltycount, rulenum, status from main_penalty, main_blacklist where main_penalty.id_blacklist_id = main_blacklist.id")
# 		rows = cur.fetchall()

# 		for row in rows:
# 			p = PenaltyInfo(row[0], row[1], row[2], row[3], row[4], row[5])
# 			arr.append(p) #.add

# 		return arr

