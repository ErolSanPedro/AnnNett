from django.shortcuts import render
from django.http import HttpResponse
from threading import Thread,Condition
from django.utils.timezone import now
from django.core import serializers
from django.db.models import Max , Min, Q
from datetime import datetime
from scapy.all import *
from .models import *
import configparser
import threading
import serial
import random
import json
import re
from logging import Filter

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
RULENUM_LIST = []
IP_LIST = [] #never used
ALLRULES_LIST = []

serialLock = threading.Semaphore()


# for var in PENALTY_TABLE:
# 	RULENUM_LIST.append(var.rulenum)

RULENUM_LIST = list(PENALTY_TABLE.filter(status='blocked').values_list('rulenum', flat=True))

for x in range(1,1000): #changed from 
	ALLRULES_LIST.append(x*2000)

for var in BLACKLIST_TABLE: #never used
	IP_LIST.append(var.ipaddress) #never used

rulesList = ALLRULES_LIST.copy()

MX = PENALTY_TABLE.filter(penaltycount=1, status='blocked').aggregate(MX=Max('rulenum'))['MX'] or 1 #changed from 0 since thres no assigned rule num 0 #added filter
MN = PENALTY_TABLE.filter(penaltycount=1, status='blocked').aggregate(MN=Min('rulenum'))['MN'] or 1998000 # added filter
MRUq = list(PENALTY_TABLE.filter( Q(status='archived') | Q(status='inactive')).order_by('status', 'lastaccessed').values_list('rulenum', flat=True))
LRUq = list(PENALTY_TABLE.filter( Q(status='archived') | Q(status='inactive')).order_by('status', '-lastaccessed').values_list('rulenum', flat=True))
LFU = PENALTY_TABLE.filter(penaltycount=1, status='blocked').aggregate(MX=Max('rulenum'))['MX'] or 0 #changed from -1
MFU = PENALTY_TABLE.filter(penaltycount=1, status='blocked').aggregate(MN=Max('rulenum'))['MN'] or 1995999

MRU_filtered = []
LRU_filtered = []

print(RULENUM_LIST)

for x in ALLRULES_LIST:
	if x in RULENUM_LIST:
		rulesList.remove(x)
rulesList.sort()
emptyMRU = rulesList[0]
rulesList.sort(reverse = True)
emptyLRU = rulesList[0]

for x in MRUq:
	if x not in RULENUM_LIST:
		MRU_filtered.append(x)
	
for x in LRUq:
	if x not in RULENUM_LIST:
		LRU_filtered.append(x)

#print('start_mru list2 -' + str(MRU_filtered))
#print('start_lru list2 -' + str(LRU_filtered))


if MRU_filtered:
	MRU = int(MRU_filtered[0])
else:
	MRU = MX
	
if emptyMRU < MRU:
	MRU = emptyMRU

if LRU_filtered:
	LRU = int(LRU_filtered[0])
else:
	LRU = MN

if emptyLRU > LRU:
	LRU = emptyLRU


# Its placement is based on insertion. The new penalty is gonna be placed in an order where it can be the first for MRU
# And for LRU where it can be the least in the router. So it can be that the newest is at the last possible line. 

if config['SETTINGS']["sort_mode"] == 'lru':
	# nextACL = -2000

	if (MN < LRU and MN != 1998000):
		startingACLnmbr = LRU

	elif LRU_filtered:
		if LRU_filtered[0] == MN:
			startingACLnmbr = MN
		else:
			startingACLnmbr = MN - 2000
	else:
		startingACLnmbr = MN
	
elif (config['SETTINGS']["sort_mode"] == "mru"):
	# nextACL = 2000

	if (MX > MRU and MX != 0):
		startingACLnmbr = MRU
	elif MRU_filtered:
		if MRU_filtered[0] == MX:
			startingACLnmbr = MX
		else:
			startingACLnmbr = MX + 2000	
	else:	
		startingACLnmbr = MX

elif (config['SETTINGS']["sort_mode"] == "rr"):
	
	if (MX > MRU and MX != 0):
		startingACLnmbr = MRU

	elif MRU_filtered:
		if MRU_filtered[0] == MX:
			startingACLnmbr = MX
		else:
			startingACLnmbr = MX + 2000	
	else:	
		startingACLnmbr = MX + 2000

elif (config['SETTINGS']["sort_mode"] == "mfu"):
	startingACLnmbr = MFU + 1
	
elif (config['SETTINGS']["sort_mode"] == "lfu"):
	startingACLnmbr = LFU + 1

print("=============CURRENT SETTINGS==============")
print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " RESET_TIME: " + str(config['SETTINGS']["reset_time"]))
print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " BASE_PENALTY_TIME: " + str(config['SETTINGS']["base_penalty_time"]))
print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " LIFT_ARRAY_SIZE: " + str(config['SETTINGS']["lift_array_size"]))
print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " AUTO_LIFT_TIMER: " + str(config['SETTINGS']["auto_lift_timer"]))
print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " SORT_MODE: " + str(config['SETTINGS']["sort_mode"]))

#print(startingACLnmbr)

#ACLcurrIndx = 0		#The index where Router rules end in PenaltyTable e.g. Penalty_Table[ACLcrrIndx] is the latest ACL rule in the router
	
i=13

#Blacklist deleting

#Blacklist.objects.all().delete()


#Blacklist addition


# with open("domains.txt","r") as f:
# 	content = f.readlines()
# 	if (content[0] != readable_hash):
# 		for con in content:
# 			if (not bool(re.findall('[a-zA-Z]', con))):	
# 				new_blacklist = Blacklist(ipaddress = con)
# 				new_blacklist.save()

# eldes 
# 	
# with open("domains.txt","r") as f:
# 	content = f.readlines()
# 	for con in content:
# 		if (not bool(re.findall('[a-zA-Z]', con))):	
# 			con = con.strip()
# 			new_blacklist = Blacklist(ipaddress = con)
# 			new_blacklist.save()

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
	def __init__(self, src_IP, dest_IP, src_mac, dest_port):
		self.src_IP = src_IP
		self.dest_IP = dest_IP
		self.src_mac = src_mac
		self.dest_port = dest_port


#=============================PROGRAM CODE==============================================================

def parseModule(pkt):
	if IP in pkt and TCP in pkt: #added port filtering
		ntwk_info = network_info(pkt[IP].src, pkt[IP].dst, pkt[Ether].src, pkt[TCP].dport) #added port
		verificationModule(ntwk_info)

	# if IP in pkt: #added port filtering
	# 	ntwk_info = network_info(pkt[IP].src, pkt[IP].dst, pkt[Ether].src, "80") #icmping
	# 	verificationModule(ntwk_info)


#added port filtering
def verificationModule(info):
	global BLACKLIST_TABLE
	global PENALTY_TABLE
	global AUDIT_TABLE
	global AUDIT_LIST

	for var in PENALTY_TABLE:
		for blkListVar in BLACKLIST_TABLE:
			if blkListVar == var.id_blacklist:
				if (str(blkListVar.ipaddress) == str(info.dest_IP)) and (str(blkListVar.port) == str(info.dest_port)):
					#have I seen this before and just need to increase penalty?	
					if var.status == 'blocked':

						#AUDIT DB is a complete list of mac addr/src IP that accessed Blacklisted ip addresses
						print(str(info.dest_IP) + ' IS CURRENTLY BLOCKED')
						#addToAudit(info)
					
						#Drop Traffic
						return

					#Is already in the Penalty DB
					#Needs new status
					###Can just skip to penaltyModule
					blacklistModule(info)

	#End of Table, could be a new penalty

	blacklistModule(info)

def blacklistModule(info):
	#global IP_LIST
	global BLACKLIST_TABLE

	# if info.dest_IP in IP_LIST:
	# 	print('blacklist')
	# 	#ITS a Blacklisted IP!!!
	# 	penaltyModule(info, var)

	for b in BLACKLIST_TABLE:
		if str(b.ipaddress) == str(info.dest_IP) and str(b.port) == str(info.dest_port):
			penaltyModule(info, b) 

def penaltyModule(info, b):
	#global IP_LIST
	global PENALTY_TABLE
	global PENALTY_LIST
	global RULENUM_LIST
	#global LIFT_LIST
	#global AUDIT_LIST
	global UPDATE_LIST
	global startingACLnmbr
	global config

	isInList=None #so I don't have repeats of IP address in Penalty list

	ACLruleNum = startingACLnmbr 
	
	for var in PENALTY_TABLE:
		#changed from b.ipaddress, since 2 ipaddress = diff port will be
		if str(b.id) == str(var.id_blacklist) and (b.ipaddress == info.dest_IP) and str(b.port) == str(info.dest_port) and (var.status != 'blocked') and (var not in UPDATE_LIST): 
			#Just needs to update status and rulenum
			#print("old penalty")
			#print(info.dest_IP)
			var.id = var.id
			var.lastaccessed = now()	
			var.penaltycount = var.penaltycount + 1


			if config['SETTINGS']['sort_mode'] == 'mfu': 
				checkACLruleNum = PENALTY_TABLE.filter(penaltycount=var.penaltycount, status='blocked').aggregate(MX=Max('rulenum'))['MX'] #added blocked status
				if checkACLruleNum:
					ACLruleNum = checkACLruleNum + 1	
				else:
					ACLruleNum = 2000000 - (var.penaltycount*2000)
				
				var.rulenum = ACLruleNum
			elif config['SETTINGS']['sort_mode'] == 'lfu':
				checkACLruleNum = PENALTY_TABLE.filter(penaltycount=var.penaltycount, status='blocked').aggregate(MX=Max('rulenum'))['MX'] #added blocked status
				print(checkACLruleNum)
				if checkACLruleNum: #may nauna na sa range n un
					ACLruleNum = checkACLruleNum + 1	
				else: #first on that range
					if var.penaltycount-1 != 0: #needs to do this kasi magiging 0 yung rulenum pagnagkataon
						ACLruleNum = (var.penaltycount-1)*2000 
					elif var.penaltycount-1 == 0:
						ACLruleNum = 1 #pag 0, auto to 1
				
				var.rulenum = ACLruleNum
			else:
				var.rulenum = ACLruleNum

			var.status = "blocked" #nilagay ko sa dulo kasi massama yuung mga archived at inactive na wala pang rulenum

			#print(checkACLruleNum)
			startingACLnmbr = nextACL(config['SETTINGS']['sort_mode'], ACLruleNum)

			UPDATE_LIST.append(var)
			addToAudit(info)
			# ACLConfigModule(info, var.rulenum)
			ACLConfigModule(var, b)

	#============NEW PENALTY================

	for var in PENALTY_TABLE:  #changed into id instead
		if str(b.id) == str(var.id_blacklist) and str(b.ipaddress) == str(info.dest_IP) and str(b.port) == str(info.dest_port):
			isInList = 1

	for var in PENALTY_LIST:
		if str(b.id) == str(var.id_blacklist) and str(b.ipaddress) == str(info.dest_IP) and str(b.port) == str(info.dest_port):
			isInList = 1

	#Conditions so we don't have repeating IP addresses

	if isInList is None:
		#print("new penalty")
	
		new_penalty = Penalty(id_blacklist= b,
							lastaccessed= now(), 
							penaltycount= 1,
							rulenum= ACLruleNum,
							status= 'blocked')

		PENALTY_LIST.append(new_penalty)

		addToAudit(info)
		# ACLConfigModule(info, ACLruleNum)
		ACLConfigModule(new_penalty, b)
		startingACLnmbr = nextACL(config['SETTINGS']['sort_mode'], ACLruleNum)
		#print('next - ' + str(startingACLnmbr))


def addToAudit(info):
	global AUDIT_LIST

	#print("Adding to Audit")
	AUDIT_LIST.append(Audit(sourceip= info.src_IP,
							macaddress= info.src_mac,
							time= now()))

def nextACL(sortMode,oldACL):
	
	global PENALTY_TABLE
	global PENALTY_LIST
	global RULENUM_LIST
	global ALLRULES_LIST

	rulesList = ALLRULES_LIST.copy()

	if oldACL is not None:
		if oldACL not in RULENUM_LIST:
			RULENUM_LIST.append(oldACL)
	
	for y in PENALTY_LIST:
		if y.rulenum not in RULENUM_LIST:
			RULENUM_LIST.append(y.rulenum)

	MRU_filtered = []
	LRU_filtered = []

	if RULENUM_LIST: 
		MX = max(RULENUM_LIST)
		MN = min(RULENUM_LIST)
	else:
		MX = 1 #changed from
		MN = 1998000

	MRUq = list(PENALTY_TABLE.filter( Q(status='archived') | Q(status='inactive')).order_by('status', 'lastaccessed').values_list('rulenum', flat=True))
	LRUq = list(PENALTY_TABLE.filter( Q(status='archived') | Q(status='inactive')).order_by('status', '-lastaccessed').values_list('rulenum', flat=True))
	LFU = PENALTY_TABLE.filter(penaltycount=1, status='blocked').aggregate(MX=Max('rulenum'))['MX'] or 0 #changed from -1
	MFU = PENALTY_TABLE.filter(penaltycount=1, status='blocked').aggregate(MX=Max('rulenum'))['MX'] or 1995999

	if PENALTY_LIST:
		for v in PENALTY_LIST:
			if v.rulenum > LFU:
				LFU = v.rulenum
			if v.rulenum > MFU:
				MFU = v.rulenum

	#print("starting nextACL" + str(RULENUM_LIST))
	#print(oldACL)
	#print("rulesList - " + str(rulesList[:5]))

	intRULENUM_LIST = list(map(int, RULENUM_LIST))

	#print("if {}".format(intRULENUM_LIST))

	for x in ALLRULES_LIST:
		if x in intRULENUM_LIST:
			#print("removing {}".format(x))
			rulesList.remove(x)

	rulesList.sort()
	emptyMRU = rulesList[0]
	#print("rulesList - " + str(rulesList[:5]))

	rulesList.sort(reverse = True)
	emptyLRU = rulesList[0]

	#print("rulesListR - " + str(rulesList[:5]))
	#print(MX, MN)

	#print('lru list -' + str(LRUq))

	for x in MRUq:
		if x not in RULENUM_LIST:
			MRU_filtered.append(x)
		
	for x in LRUq:
		if x not in RULENUM_LIST:
			LRU_filtered.append(x)

	#print('mru list2 -' + str(MRU_filtered))
	#print('lru list2 -' + str(LRU_filtered))

	if MRU_filtered:
		MRU = int(MRU_filtered[0])
	elif MX not in RULENUM_LIST:
		MRU = MX
	else:
		MRU = emptyMRU

	if emptyMRU < MRU:
		MRU = emptyMRU

	if LRU_filtered:
		LRU = int(LRU_filtered[0])
	elif MN not in RULENUM_LIST:
		LRU = MN
	else:
		LRU = emptyLRU

	if emptyLRU > LRU:
		LRU = emptyLRU
		

	#print(sortMode + " Mode")

	if sortMode == 'rr':
		newACL = 2000*random.randint(1, 999) #change from 1000
		while newACL in RULENUM_LIST:
			newACL = 2000*random.randint(1, 999)

	if sortMode == 'mru':
		newACL = MRU
			
		# if (MX >= MRU and MX != 0):
		# 	newACL = MRU

		# elif MRU_filtered:
		# 	if MRU_filtered[0] == MX:
		# 		newACL = MX
		# 	else:
		# 		newACL = MX + 2000
		# else:
		# 	newACL = MX
	if sortMode == 'lru':
		newACL = LRU

	if sortMode == 'mfu':
		newACL = MFU + 1

	if sortMode == 'lfu':
		newACL = LFU + 1

	#print("new {} \n{}".format(newACL, RULENUM_LIST))
	return newACL



#@background?
#def ACLConfigModule(info, rulenum):
def ACLConfigModule(p_info, b_info):
	
	# Adds to the router as soon as it receives a packet that is blacklisted. We are focusing on maximum security

	#alternate variation is we can run as an asynchronous thread that runs while true, so that we don't keep opening 
	#and closing the router connection
	serialLock.acquire()

	print("======== ACL CONFIG MODULE ========")
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " enable ")
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " configure terminal ")


	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " int fa0/1 ")
	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " no ip access-group blacklist in ")
	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " exit ")

	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " ip access-list extended blacklist ")
	# if (rulenum != 2000):
	# 	commandNo = "no {} ".format(rulenum)
	# 	print(commandNo + str(datetime.now().time()))
	#command = "{} deny icmp host {} any ".format(p_info.rulenum, b_info.ipaddress) #note that ICMP packets do not take a port number
	
	command = str(p_info.rulenum) + " deny tcp host " + str(b_info.ipaddress) + " any eq " + str(b_info.port)
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "] " + command)

	# command = "{} permit icmp any any ".format((rulenum + 2000)) #note that any any should always be the last
	# print(command + str(datetime.now().time()))

	#print("exit "  + str(datetime.now().time()))
	
	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " int fa0/1 ")
	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " ip access-group blacklist in ")

	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " exit ")
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " exit ")

	print("======== END OF ACL CONFIG MODULE ========")

	# ser = serial.Serial('COM5')
	# ser.write(b"\n")
	# ser.write(b"enable\n")
	# ser.write(b"configure terminal\n")


	# ser.write(b"int fa0/1\n")
	# ser.write(b"no ip access-group blacklist in\n")
	# ser.write(b"exit\n")

	# ser.write(b"ip access-list extended blacklist\n")
	# if (rulenum != 2000):
	# 	commandNo = "No {}\n".format(rulenum)
	# 	ser.write(commandNo.encode())
	# command = "{} deny icmp host {} any\n".format(rulenum, info.dest_IP) #note that ICMP packets do not take a port number
	# ser.write(command.encode())

	# command = "{} permit icmp any any\n".format((rulenum + 2000)) #note that any any should always be the last
	# ser.write(command.encode())

	# ser.write(b"exit\n")
	
	# ser.write(b"int fa0/1\n")
	# ser.write(b"ip access-group blacklist in\n")

	# ser.write(b"exit\n")
	# ser.write(b"exit\n")
	
	# ser.close()

	serialLock.release()


def main():
	#print("starting")
	#parseModule()
	sniff(iface='Wi-Fi', prn=parseModule, count = 0, store=0)

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

	global RULENUM_LIST
	global startingACLnmbr
	
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
				del PENALTY_LIST[:len(PENALTY_LIST)] #1,586,054,549 12,688,379,167
				#3,172,093,331

		#86400 seconds in a day
		#RESET TIME - di na need maglgay pa ng var.rulenum = 0 kasi sa inactive palang nareset back to 0 na e
		for var in PENALTY_TABLE:
			ResetTime = (float(adminConfig['reset_time']) * 60) + var.lastaccessed.timestamp()
			BaseTime =  float(adminConfig['base_penalty_time']) * 60 * var.penaltycount
			calulateResetTime = ResetTime + BaseTime - int(now().timestamp())

			#if( var.status != 'archived'): #just stop debugging after status changed to archived
				#print("Reset time for PenID: " + str(var.id) + " " + str(round(calulateResetTime, 2)))

			#ginawa ko to para naman di secs remaining tsaka sya mag archived from inactive. walang kwenta pag ganun
			if calulateResetTime <= 0: #86400 changed
				if( var.status != 'archived'):
					var.id = var.id
					var.status = 'archived'
					var.penaltycount = 0 # added
					UPDATE_LIST.append(var) 
					print("[" + str(datetime.now().time().replace(microsecond = 0)) + "]" + " ARCHIVED PenID: " + str(var.id))


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
				# print((((int(adminConfig['base_penalty_time'])*60)*(var.penaltycount))+var.lastaccessed.timestamp()))
				# print(int(now().timestamp()))

				# print( int(now().timestamp()) - (((int(adminConfig['base_penalty_time'])*60)*(var.penaltycount))+var.lastaccessed.timestamp()))

				# s = (float(adminConfig['base_penalty_time'])*60)) - float(now().timestamp())
				# print("dito " + str(s))

				BaseTime =  float(adminConfig['base_penalty_time']) * 60 * var.penaltycount + var.lastaccessed.timestamp()

				#print("Lift time for PenID: " + str(var.id) + " " + str(round(calulateResetTime, 2)))

				if BaseTime <= int(now().timestamp()):
					var.id = var.id
					var.status = 'inactive'
					if var.rulenum in RULENUM_LIST:
						RULENUM_LIST.remove(var.rulenum)
					expiryLiftModule(var)
					UPDATE_LIST.append(var)
					#var.rulenum = 0 # reset para di magulo, can't add kasi nakabase dito ung insertion method later on					



		if ( (len(UPDATE_LIST)>=arraySize) or ( timer == 0 )):
			
			if((len(UPDATE_LIST)>=arraySize)):
				print("inside3")
				Penalty.objects.bulk_update(UPDATE_LIST, ['lastaccessed','status','penaltycount','rulenum'], arraySize)
				PENALTY_TABLE = Penalty.objects.all()
				del UPDATE_LIST[:arraySize]
			elif (timer == 0) and (len(UPDATE_LIST) is not 0):
				print('Updating - {}'.format(RULENUM_LIST))

				Penalty.objects.bulk_update(UPDATE_LIST, ['lastaccessed','status','penaltycount','rulenum'], len(UPDATE_LIST))
				PENALTY_TABLE = Penalty.objects.all()
				RULENUM_LIST = list(PENALTY_TABLE.filter(status='blocked').values_list('rulenum', flat=True))
				del UPDATE_LIST[:len(UPDATE_LIST)]
				print('Updated - {}'.format(RULENUM_LIST))
				startingACLnmbr = nextACL(config['SETTINGS']['sort_mode'], None)

		#================DELETING ACL RULES=========================




		#if (timer == 0):
			#print("Tried to Update at " + str(datetime.now().time()))
			#print(len(PENALTY_LIST))
			#print(len(UPDATE_LIST))
		time.sleep(0.4)			

def expiryLiftModule(ACLrule):

	print("Attempting Lift")
	serialLock.acquire()

	print("======== EXPIRY LIFT MODULE ========")
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " enable ")
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " configure terminal ")


	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " int fa0/1 ")
	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " no ip access-group blacklist in ")
	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " exit ")

	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " ip access-list extended blacklist ")
	# command = "no {} \n".format(ACLrule.rulenum)
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " no {}  ".format(ACLrule.rulenum))
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " exit ")
	
	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " int fa0/1 ")
	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " ip access-group blacklist in ")

	# print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " exit ")
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " exit ")

	print("======== END OF EXPIRY LIFT MODULE ========")
	
	# ser = serial.Serial('COM5')
	# ser.write(b"\n")
	# ser.write(b"enable\n")
	# ser.write(b"configure terminal\n")


	# ser.write(b"int fa0/1\n")
	# ser.write(b"no ip access-group blacklist in\n")
	# ser.write(b"exit\n")

	# ser.write(b"ip access-list extended blacklist\n")
	# # command = "no {} \n".format(ACLrule.rulenum)
	# ser.write("no {} \n".format(ACLrule.rulenum).encode())
	# ser.write(b"exit\n")
	
	# ser.write(b"int fa0/1\n")
	# ser.write(b"ip access-group blacklist in\n")

	# ser.write(b"exit\n")
	# ser.write(b"exit\n")
	
	# ser.close()

	serialLock.release()

def sortingModule(sortAlgo):
	global PENALTY_TABLE
	global RULENUM_LIST
	global startingACLnmbr

	#Penalty.objects.all().delete()
	PENALTY_TABLE = Penalty.objects.all()
	RULENUM_LIST = []

	if sortAlgo in ['mru','rr','lfu']:
		startingACLnmbr = 1 # changed from 0 since there's no 0 in assigned acl
	elif sortAlgo == 'lru':
		startingACLnmbr = 1998000
	elif sortAlgo == 'mfu':
		startingACLnmbr = 1996000

	print("Attempting Delete")
	serialLock.acquire()
	# print("enable " + str(datetime.now().time()))
	# print("configure terminal " + str(datetime.now().time()))


	# print("int fa0/1 " + str(datetime.now().time()))
	# print("no ip access-group blacklist in " + str(datetime.now().time()))
	# print("exit " + str(datetime.now().time()))

	# print("no ip access-list extended blacklist " + str(datetime.now().time()))
	# print("ip access-list extended blacklist " + str(datetime.now().time()))
	# print("no sh "  + str(datetime.now().time()))
	# print("exit " + str(datetime.now().time()))
	
	# print("int fa0/1 " + str(datetime.now().time()))
	# print("ip access-group blacklist in " + str(datetime.now().time()))

	# print("exit " + str(datetime.now().time()))
	# print("exit " + str(datetime.now().time()))

	# ser = serial.Serial('COM5')
	# ser.write(b"\n")
	# ser.write(b"enable\n")
	# ser.write(b"configure terminal\n")


	# ser.write(b"int fa0/1\n")
	# ser.write(b"no ip access-group blacklist in\n")
	# ser.write(b"exit\n")

	# ser.write(b"no ip access-list extended blacklist\n")
	# ser.write(b"ip access-list extended blacklist\n")
	# ser.write(b"no sh\n")
	# ser.write(b"exit\n")
	
	# ser.write(b"int fa0/1\n")
	# ser.write(b"ip access-group blacklist in\n")

	# ser.write(b"exit\n")
	# ser.write(b"exit\n")
	
	#ser.close()

	serialLock.release()
	

#==============================Running Django============================================================

#print("Thread start")
x = threading.Thread(target=updateModule, args=())
x.daemon = True
x.start()

d = threading.Thread(target=main, args=())
d.daemon = True
d.start()

def index(request):

	blacklist = Blacklist.objects.all()
	penaltylist = Penalty.objects.all()
	#print(penaltylist)
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
		'reset_time': float(adminConfig["reset_time"]), 
		'base_penalty': float(adminConfig["base_penalty_time"]),
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

	print("=============NEW SETTINGS==============")
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " RESET_TIME: " + str(config['SETTINGS']["reset_time"]))
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " BASE_PENALTY_TIME: " + str(config['SETTINGS']["base_penalty_time"]))
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " LIFT_ARRAY_SIZE: " + str(config['SETTINGS']["lift_array_size"]))
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " AUTO_LIFT_TIMER: " + str(config['SETTINGS']["auto_lift_timer"]))
	print("[" + str(datetime.now().time().replace(microsecond=0)) + "]" + " SORT_MODE: " + str(config['SETTINGS']["sort_mode"]))


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
	global BLACKLIST_TABLE

	#combined = list(chain(PENALTY_TABLE, BLACKLIST_TABLE))
	#print(combined)

	#or any kind of queryset
	json = serializers.serialize('json', PENALTY_TABLE)

	return HttpResponse(json, content_type='application/json')

def updateAuditTable(request):
	global AUDIT_TABLE

	#or any kind of queryset
	json = serializers.serialize('json', AUDIT_TABLE)


	return HttpResponse(json, content_type='application/json')
	# return HttpResponse(json.dumps(context))

