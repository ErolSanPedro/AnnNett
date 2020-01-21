from django.shortcuts import render
from django.http import HttpResponse
from threading import Thread,Condition
from django.utils.timezone import now
from django.core import serializers
from django.db.models import Max
from datetime import datetime
from scapy.all import *
from .models import *
import configparser
import threading
import serial
import json

# Create your views here.

#=============================DEFINITIONS AND TESTING====================================================

config = configparser.ConfigParser()
config.read ("main/config.ini")	
adminConfig = config["SETTINGS"]


BLACKLIST_TABLE = Blacklist.objects.all()
PENALTY_TABLE = Penalty.objects.all()
AUDIT_TABLE = Audit.objects.all()

# for main program

EXPIRY_LIST = []	#Master list ACL rules in the router
LIFT_LIST = [] 		#Lift LIST to be used by Expiry Lift Module
PENALTY_LIST = []	#To be used to stack the database update calls
AUDIT_LIST = []		#To be used to stack the database update calls
UPDATE_LIST = []	#List of alrdy existing penalty that needs "status" to be changed

serialLock = threading.Semaphore()


p1 = PENALTY_TABLE.annotate(num=Max('rulenum'))

if (config['SETTINGS']["sort_mode"] == "lru"):
	if p1:
		startingACLnmbr = int(p1[0].num)
	else:
		startingACLnmbr = 0
elif (config['SETTINGS']["sort_mode"] == "mru"):
	pass



ACLcurrIndx = 0		#The index where Router rules end in PenaltyTable e.g. Penalty_Table[ACLcrrIndx] is the latest ACL rule in the router
	
i=13

f=open("domains.txt", "r")


f.close()

#TESTING

# for var in BLACKLIST_TABLE:
#  	new_penalty = Penalty(id_blacklist = var, lastaccessed = datetime.now(),penaltycount = i, rulenum = 5000, status = 'who cares')
#  	PENALTY_LIST.append(new_penalty)
#  	i= i + 1

# #working
# Penalty.objects.bulk_create(PENALTY_LIST,len(PENALTY_LIST))

# PENALTY_TABLE = Penalty.objects.all()



#Working Update field
# for x in range(10):
# 	PENALTY_TABLE[x].status = 'What"chu doin'
# 	UPDATE_LIST.append(PENALTY_TABLE[x])

# Penalty.objects.bulk_update(UPDATE_LIST, ['status'])



#updating

# print(AUDIT_TABLE[len(AUDIT_TABLE)-1].time)

# new = Audit(sourceip= "info.src_IP",
# 			macaddress= "info.src_mac",
# 			time= now())

# new.save()
# AUDIT_TABLE = Audit.objects.all()

# print(AUDIT_TABLE[len(AUDIT_TABLE)-1].time)





# for var in PENALTY_TABLE:
# 	new_Audit = Audit( sourceip= "var.ipaddress", macaddress= "info.src_mac", time= now())
# 	AUDIT_LIST.append(new_Audit)

# print(len(AUDIT_LIST))
# Audit.objects.bulk_create(AUDIT_LIST,len(AUDIT_LIST))

# for var in AUDIT_LIST:
# 	print(i)
# 	var.save()
# 	i = i + 1 



class network_infoV2(object):
	src_IP = ""
	dest_IP = ""
	portNum = 0
	src_mac = ""

	def __init__(self, src_IP, dest_IP, portNum, src_mac):
		self.src_IP = src_IP
		self.dest_IP = dest_IP
		self.portNum = portNum
		self.src_mac = src_mac

class network_info(object):
	src_IP = ""
	dest_IP = ""
	src_mac = ""

	def __init__(self, src_IP, dest_IP, src_mac):
		self.src_IP = src_IP
		self.dest_IP = dest_IP
		self.src_mac = src_mac


#=============================PROGRAM CODE==============================================================

def parseModule(pkt):


	if IP in pkt:
		# ntwk_info = network_infoV2( pkt[IP].src, pkt[IP].dst, pkt[IP].dport, pkt[Ether].src)
		ntwk_info = network_info( pkt[IP].src, pkt[IP].dst, pkt[Ether].src)


		if ntwk_info.dest_IP == '192.168.1.2':
		# 172.217.17.132
			print("Verifying")
			verificationModule(ntwk_info)


def verificationModule(info):
	global BLACKLIST_TABLE
	global PENALTY_TABLE
	global AUDIT_TABLE
	global AUDIT_LIST


	####TENTATIVE

	for var in PENALTY_TABLE:
		for blkListVar in BLACKLIST_TABLE:
			if blkListVar == var.id_blacklist:
				if blkListVar.ipaddress == info.dest_IP:
					#have I seen this before and just need to increase penalty?	
					if var.status == 'blocked':

						#AUDIT DB is a complete list of mac addr/src IP that accessed Blacklisted ip addresses
						addToAudit(info)
						

						#Drop Traffic
						return

					#Is already in the Penalty DB
					#Needs new status
					###Can just skip to penaltyModule
					blacklistModule(info)
	print("Packet found")
	#=====================================Causes HANDSHAKE to be recorded?========================================

	hndShakeCnt=0

	for var in PENALTY_LIST:
		for blkListVar in BLACKLIST_TABLE:
			if (var.id_blacklist == blkListVar):
				if hndShakeCnt == 0:
					if blkListVar.ipaddress == info.dest_IP:
						addToAudit(info)
						hndShakeCnt = 1
					else:
						return

	#End of Table, could be a new penalty
	blacklistModule(info)

def blacklistModule(info):
	global BLACKLIST_TABLE

	for var in BLACKLIST_TABLE:
		if var.ipaddress == info.dest_IP:
			#ITS a Blacklisted IP!!!
			penaltyModule(info, var)


def penaltyModule(info, blacklist_var):
	global BLACKLIST_TABLE
	global PENALTY_TABLE
	global PENALTY_LIST

	global LIFT_LIST
	global AUDIT_LIST
	global UPDATE_LIST
	global startingACLnmbr

	isInList=None #so I don't have repeats of IP address in Penalty list


	#************Why do I have Penalty List and Table as separate?

	print("penalty")

	ACLruleNum = startingACLnmbr + 2000
	startingACLnmbr = ACLruleNum







	for var in PENALTY_LIST:
		for blkListVar in BLACKLIST_TABLE:
			if blkListVar == var.id_blacklist: 
				if blkListVar.ipaddress == info.dest_IP:
				#Just needs to update status and rulenum
					var.lastaccessed = now()	
					var.penaltycount = var.penaltycount + 1
					var.status = "blocked"

					UPDATE_LIST.append(var)
					addToAudit(info)

					#expiryLiftModule(info)

					ACLConfigModule(info, var.rulenum)#***************************** Will this exit back to here?
	
	#============NEW PENALTY================

	for var in PENALTY_LIST:
		for blkListVar in BLACKLIST_TABLE:
			if blkListVar == var.id_blacklist: 
				if blkListVar.ipaddress == info.dest_IP:
						isInList = 0

	#Conditions so we don't have repeating IP addresses

	if isInList is None:

		new_penalty= Penalty(id_blacklist= blacklist_var,
							lastaccessed= now(), 
							penaltycount= 1,
							rulenum= ACLruleNum,
							status= 'blocked')



		PENALTY_LIST.append(new_penalty)

		addToAudit(info)
		ACLConfigModule(info, ACLruleNum)


def addToAudit(info):
	global AUDIT_LIST

	print("Adding to Audit")
	AUDIT_LIST.append(Audit(sourceip= info.src_IP,
							macaddress= info.src_mac,
							time= now()))


#@background?
def ACLConfigModule(info, rulenum):
	# Adds to the router as soon as it receives a packet that is blacklisted. We are focusing on maximum security

	#alternate variation is we can run as an asynchronous thread that runs while true, so that we don't keep opening 
	#and closing the router connection
	serialLock.acquire()

	print("ACLConfigModule")
	ser = serial.Serial('COM5')
	ser.write(b"\n")
	ser.write(b"enable\n")
	ser.write(b"configure terminal\n")


	ser.write(b"int fa0/1\n")
	ser.write(b"no ip access-group blacklist in\n")
	ser.write(b"exit\n")

	ser.write(b"ip access-list extended blacklist\n")
	if (rulenum != 2000):
		commandNo = "No {}\n".format(rulenum)
		ser.write(commandNo.encode())
	command = "{} deny icmp host {} any\n".format(rulenum, info.dest_IP) #note that ICMP packets do not take a port number
	ser.write(command.encode())

	command = "{} permit icmp any any\n".format((rulenum + 2000)) #note that any any should always be the last
	ser.write(command.encode())

	ser.write(b"exit\n")
	
	ser.write(b"int fa0/1\n")
	ser.write(b"ip access-group blacklist in\n")

	ser.write(b"exit\n")
	ser.write(b"exit\n")
	
	ser.close()

	serialLock.release()


def main():
	print("starting")
	sniff(iface='Realtek PCIe GBE Family Controller', prn=parseModule, count = 0, store=0)

#wifi name
#Intel(R) Dual Band Wireless-AC 3165
#ethernet name
#Realtek PCIe GBE Family Controller
#main()




#==============================Asynchronous============================================================

# Needs to be updated 
# save new Penalty, 
# update old Penalties to active stored in UPDATE_LIST, 
# save new Audits, 
# update old Penalties to inactive/archived 

#@background
def updateModule():
	global PENALTY_TABLE
	global AUDIT_TABLE

	global PENALTY_LIST
	global AUDIT_LIST
	global UPDATE_LIST

	global adminConfig
	global LIFT_LIST 	#Add ACL rules to be lifted here

	global BLACKLIST_TABLE
	global PENALTY_TABLE
	global AUDIT_TABLE

	while True:
		timer = int(now().timestamp())%(int(adminConfig['auto_lift_timer']))
		arraySize = int(adminConfig['lift_array_size'])

		BLACKLIST_TABLE = Blacklist.objects.all()

		if ( (len(PENALTY_LIST)>=arraySize) or ( timer == 0 ) ):
			if((len(PENALTY_LIST)>=arraySize)):
				print("inside1")
				Penalty.objects.bulk_create(PENALTY_LIST,arraySize)
				PENALTY_TABLE = Penalty.objects.all()			
				del PENALTY_LIST[:arraySize]

			elif (timer == 0) and (len(PENALTY_LIST) is not 0):
				Penalty.objects.bulk_create(PENALTY_LIST,len(PENALTY_LIST))
				PENALTY_TABLE = Penalty.objects.all()
				del PENALTY_LIST[:len(PENALTY_LIST)]

		#86400 seconds in a day
		#RESET TIME
		if (((int(adminConfig['reset_time'])*86400)%int(now().timestamp())) == 0):
			for var in PENALTY_TABLE:
				if( var.status is not 'archived'):
					var.status = 'archived'
					UPDATE_LIST.append(var)


		if ( (len(AUDIT_LIST)>=arraySize) or ( timer == 0 )):
			if((len(AUDIT_LIST)>=arraySize)):
				print("inside2")
				Audit.objects.bulk_create(AUDIT_LIST,arraySize)
				AUDIT_TABLE = Audit.objects.all()
				del AUDIT_LIST[:arraySize]
			elif (timer == 0) and (len(AUDIT_LIST) is not 0):
				Audit.objects.bulk_create(AUDIT_LIST,len(AUDIT_LIST))
				AUDIT_TABLE = Audit.objects.all()
				del AUDIT_LIST[:len(AUDIT_LIST)]


		#PENALTY TIME
		for var in PENALTY_TABLE:
			if var.status == 'blocked':
				print((((int(adminConfig['base_penalty_time'])*60)*(var.penaltycount))+var.lastaccessed.timestamp()))
				print(int(now().timestamp()))

				print( int(now().timestamp()) - (((int(adminConfig['base_penalty_time'])*60)*(var.penaltycount))+var.lastaccessed.timestamp()))
				if (((int(adminConfig['base_penalty_time'])*60)*(var.penaltycount))+var.lastaccessed.timestamp()) <= int(now().timestamp()):
					var.status = 'inactive'
					expiryLiftModule(var)
					UPDATE_LIST.append(var)


		if ( (len(UPDATE_LIST)>=arraySize) or ( timer == 0 )):
			if((len(UPDATE_LIST)>=arraySize)):
				print("inside3")
				Penalty.objects.bulk_update(UPDATE_LIST, ['lastaccessed','status','penaltycount'], arraySize)
				PENALTY_TABLE = Penalty.objects.all()
				del UPDATE_LIST[:arraySize]
			elif (timer == 0) and (len(UPDATE_LIST) is not 0):
				Penalty.objects.bulk_update(UPDATE_LIST, ['lastaccessed','status','penaltycount'], len(UPDATE_LIST))
				PENALTY_TABLE = Penalty.objects.all()
				del UPDATE_LIST[:len(UPDATE_LIST)]
		

		#================DELETING ACL RULES=========================




		if (timer == 0):
			print("Tried to Update", now().timestamp())
			print(len(PENALTY_LIST))
			print(len(UPDATE_LIST))
		time.sleep(0.4)			

def expiryLiftModule(ACLrule):
	
	print("Attempting Lift")
	serialLock.acquire()
	ser = serial.Serial('COM5')
	ser.write(b"\n")
	ser.write(b"enable\n")
	ser.write(b"configure terminal\n")


	ser.write(b"int fa0/1\n")
	ser.write(b"no ip access-group blacklist in\n")
	ser.write(b"exit\n")

	ser.write(b"ip access-list extended blacklist\n")
	# command = "no {} \n".format(ACLrule.rulenum)
	ser.write("no {} \n".format(ACLrule.rulenum).encode())
	ser.write(b"exit\n")
	
	ser.write(b"int fa0/1\n")
	ser.write(b"ip access-group blacklist in\n")

	ser.write(b"exit\n")
	ser.write(b"exit\n")
	
	ser.close()

	serialLock.release()

def sortingModule(sortAlgo):

	if(sortAlgo == 'mru'):
		pass

	if(sortAlgo == 'lru'):
		pass

	if(sortAlgo == 'rr'):
		pass

	if(sortAlgo == 'mfu'):
		pass
	
	if(sortAlgo == 'lfu'):
		pass
	

#==============================Running Django============================================================

print("Thread start")
x = threading.Thread(target=updateModule, args=())
x.daemon = True
x.start()

d = threading.Thread(target=main, args=())
d.daemon = True
d.start()

def index(request):

	blacklist = Blacklist.objects.all()
	penaltylist = Penalty.objects.all()
	auditlist = Audit.objects.all()

	context = {
		'blacklist': 	blacklist,
		'penaltylist': 	penaltylist,
		'auditlist':	auditlist,
		}

	return render(request, 'indexSB.html', context=context)

def settings(request):
	global adminConfig

	context = {
		'reset_time': int(adminConfig["reset_time"]), 
		'base_penalty': int(adminConfig["base_penalty_time"]),
		'lift_size': int(adminConfig["lift_array_size"]),
		'lift_timer': int(adminConfig["auto_lift_timer"]),
		'sort_mode': adminConfig["sort_mode"],
	}

	return render(request, 'settings.html', context=context)

def updateconf(request):
	global config

	newResetTime = request.POST.get('reset_time')
	newBasePenaltyTime = request.POST.get("base_penalty")
	newLiftArraySize = request.POST.get("lift_size")
	newLiftTimer = request.POST.get("lift_timer")
	newSortMode = request.POST.get("sort_mode")

	if (newSortMode != config['SETTINGS']['sort_mode']):
		sortingModule(str(newSortMode))



	config['SETTINGS']["reset_time"] = newResetTime
	config['SETTINGS']["base_penalty_time"] = newBasePenaltyTime
	config['SETTINGS']["lift_array_size"] = newLiftArraySize
	config['SETTINGS']["auto_lift_timer"] = newLiftTimer
	config['SETTINGS']["sort_mode"] = newSortMode

	with open('main/config.ini', 'w') as f:
		config.write(f)

	# print("config.ini: updated")


	context = {
		'reset_time': newResetTime,
		'base_penalty': newBasePenaltyTime,
		'lift_size': newLiftArraySize,
		'lift_timer': newLiftTimer,
		'sort_mode': newSortMode,
		'source': 'system settings',
		'type': "modify",
	}

	return HttpResponse(json.dumps(context))

def updateBlacklistTable(request):
	global BLACKLIST_TABLE

	#or any kind of queryset
	json = serializers.serialize('json', BLACKLIST_TABLE)


	return HttpResponse(json, content_type='application/json')
	# return HttpResponse(json.dumps(context))


def updatePenaltyTable(request):
	global PENALTY_TABLE

	#or any kind of queryset
	json = serializers.serialize('json', PENALTY_TABLE)

	return HttpResponse(json, content_type='application/json')

def updateAuditTable(request):
	global AUDIT_TABLE

	#or any kind of queryset
	json = serializers.serialize('json', AUDIT_TABLE)


	return HttpResponse(json, content_type='application/json')
	# return HttpResponse(json.dumps(context))


# from main.models import Book, Author, BookInstance, Genre

# def index(request):
#	  """View function for home page of site."""

#	  # Generate counts of some of the main objects
#	  num_books = Book.objects.all().count()
#	  num_instances = BookInstance.objects.all().count()
	 
#	  # Available books (status = 'a')
#	  num_instances_available = BookInstance.objects.filter(status__exact='a').count()
	 
#	  # The 'all()' is implied by default.	 
#	  num_authors = Author.objects.count()
	 
#	  context = {
#			'num_books': num_books,
#			'num_instances': num_instances,
#			'num_instances_available': num_instances_available,
#			'num_authors': num_authors,
#	  }

#	  # Render the HTML template index.html with the data in the context variable
#	  return render(request, 'index.html', context=context)