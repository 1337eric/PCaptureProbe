import sys
from scapy.all import *

pcapFile = sys.argv[1]

rawDataTempList = {}
sourcePortsTempList = {}
destinationPortTempList = {}
sourceIPsTempList = {}
packetLengthTempList = {}
packetTypeTempList = {}

UDPCount = 0
TCPCount = 0
attackType = "N/A"


AmplificationPorts = {
	7001 : "AFS",
	6881 : "BitTorrent",
	5683 : "CoAP",
	5351 : "NAT-PMP",
	53413 : "NETIS",
	5093 : "Sentinel",
	5060 : "SIP",
	502 : "Modbus",
	500 : "IPSec",
	41794 : "CrestronCip",
	389 : "cLDAP",
	3784 : "BFD",
	37810 : "DahuaDVR",
	3702 : "WSD",
	3478 : "STUN",
	8088 : "STUN",
	37833 : "STUN",
	3389 : "RDP",
	33848 : "JenkinsHudson",
	3283 : "ARD",
	32414 : "PlexMS",
	30718 : "LantronixIoT",
	30120 : "FIVEM",
	20100 : "Quake3",
	26000 : "Quake3",
	27960 : "Quake3",
	28070 : "Quake3",
	28960 : "Quake3",
	29070 : "Quake3",
	29253 : "Quake3",
	30720 : "Quake3",
	27960 : "SteamRemotePlay",
	2302 : "SRCDS",
	2303 : "SRCDS",
	2602 : "SRCDS",
	27015 : "SRCDS",
	27016 : "SRCDS",
	27017 : "SRCDS",
	27018 : "SRCDS",
	27019 : "SRCDS",
	27020 : "SRCDS",
	27021 : "SRCDS",
	27302 : "SRCDS",
	45983 : "SRCDS",
	29392 : "SRCDS",
	26742 : "SRCDS",
	52084 : "SRCDS",
	28015 : "SRCDS",
	21025 : "SRCDS",
	25244 : "SRCDS",
	2362 : "Digiman",
	20811 : "PowerhouseMangement",
	1900 : "SSDP",
	177 : "XDMCP",
	17185 : "vxWorks",
	17 : "QOTD",
	161 : "SNMP",
	1604 : "Citrix",
	1434 : "MSSQL",
	137 : "NetBIOS",
	1194 : "OpenVPN",
	11211 : "MemcacheD",
	111 : "Portmap",
	10074 : "TP240",
	10001 : "Ubiquiti",
	10001 : "Ubiquiti",
	123 : "NTP"
}

pcapLength = 0

def findIndexOfKeyFromValue(dictionary, value):
	for i in dictionary:
		if dictionary[i] == value:
			return i
		else:
			pass
	return 0

def analyzePcap(pcapFile):
	global rawDataTempList
	global sourcePortsTempList
	global destinationPortTempList
	global sourceIPsTempList
	global packetLengthTempList
	global packetTypeTempList
	global UDPCount
	global TCPCount
	global pcapLength
	packetIndex = 0
	formattedPcap = rdpcap(pcapFile)
	pcapLength = len(formattedPcap)
	for pkt in formattedPcap:
		try:
			#print(f"[{str(i)}] "+ "Source IP:"+pkt["IP"].src + " | Raw Data: " + str(pkt["Raw"].load))
			try:
				try:
					rawDataTempList[str(pkt["Raw"].load)] += 1
				except:
					rawDataTempList[str(pkt["Raw"].load)] = 0
					rawDataTempList[str(pkt["Raw"].load)] += 1
			except:
				pass
	
			try:
				sourcePortsTempList[pkt["IP"].sport] += 1
			except:
				sourcePortsTempList[pkt["IP"].sport] = 0
				sourcePortsTempList[pkt["IP"].sport] += 1
	
			try:
				destinationPortTempList[pkt["IP"].dport] += 1
			except:
				destinationPortTempList[pkt["IP"].dport] = 0
				destinationPortTempList[pkt["IP"].dport] += 1
	
			try:
				sourceIPsTempList[pkt["IP"].src] += 1
			except:
				sourceIPsTempList[pkt["IP"].src] = 0
				sourceIPsTempList[pkt["IP"].src] += 1
			try:
				try:
					TCPCount += 1
					packetLengthTempList[pkt["TCP"].len] += 1
				except:
					packetLengthTempList[pkt["TCP"].len] = 0
					packetLengthTempList[pkt["TCP"].len] += 1
					TCPCount += 1
			except:
				pass
	
			try:
				try:
					UDPCount += 1
					packetLengthTempList[pkt["UDP"].len] += 1
				except:
					packetLengthTempList[pkt["UDP"].len] = 0
					packetLengthTempList[pkt["UDP"].len] += 1
					UDPCount += 1
			except:
				pass
	
			try:
				try:
					packetTypeTempList[str(pkt["IP"].proto)] += 1
				except:
					packetTypeTempList[str(pkt["IP"].proto)] = 0
					packetTypeTempList[str(pkt["IP"].proto)] += 1
			except:
				pass
	
	
		except:
			pass
		packetIndex += 1

def checkAttackIsKnownAmp(sourceport):
	global attackType
	for port in AmplificationPorts:
		if sourceport == port:
			attackType = "Amplification - " + AmplificationPorts[port]

analyzePcap(pcapFile)

os.system("cls")

print("""                                                                                \x1b[32m.-""`""-.    
  ____                 _                    ____            _                _/`\x1b[0moOoOoOoOo`\x1b[32m\\_
 |  _ \\ ___ __ _ _ __ | |_ _   _ _ __ ___  |  _ \\ _ __ ___ | |__   ___  \x1b[32m    '.-=-=-=-=-=-=-.
 | |_) / __/ _` | '_ \\| __| | | | '__/ _ \\ | |_) | '__/ _ \\| '_ \\ / _ \\       `-=.=-.-=.=-'  
 |  __/ (_| (_| | |_) | |_| |_| | | |  __/ |  __/| | | (_) | |_) |  __/          ^  ^  ^      
 |_|   \\___\\__,_| .__/ \\__|\\__,_|_|  \\___| |_|   |_|  \\___/|_.__/ \\___|       ^           ^
                |_|                                                        ^                 ^   
                                     \x1b[32mB\x1b[0my \x1b[32mE\x1b[0mr\x1b[32mi\x1b[0mc\x1b[32m""")

sourcePortOccuredMax = max(sourcePortsTempList.values())
sourcePortMaxOccuredValue = findIndexOfKeyFromValue(sourcePortsTempList, sourcePortOccuredMax)
print(f"\x1b[32m(\x1b[0m!\x1b[32m) \x1b[0mSource port \x1b[32m"+str(sourcePortMaxOccuredValue).replace("{", "").replace("}", "")+" \x1b[0moccured \x1b[32m" + str(sourcePortOccuredMax) + " \x1b[0mtimes")

destinationPortOccuredMax = max(destinationPortTempList.values())
destinationPortMaxOccuredValue = findIndexOfKeyFromValue(destinationPortTempList, destinationPortOccuredMax)

print(f"\x1b[32m(\x1b[0m!\x1b[32m) \x1b[0mDestination port \x1b[32m"+str(destinationPortMaxOccuredValue).replace("{", "").replace("}", "")+" \x1b[0moccured \x1b[32m" + str(destinationPortOccuredMax) + " \x1b[0mtimes")

sourceIPOccuredMax = max(sourceIPsTempList.values())
sourceIPMaxOccuredValue = findIndexOfKeyFromValue(sourceIPsTempList, sourceIPOccuredMax)

print(f"\x1b[32m(\x1b[0m!\x1b[32m) \x1b[0mSource IP \x1b[32m"+str(sourceIPMaxOccuredValue).replace("{", "").replace("}", "")+" \x1b[0moccured \x1b[32m" + str(sourceIPOccuredMax) + " \x1b[0mtimes")

packetLengthOccuredMax = max(packetLengthTempList.values())
packetLengthMaxOccuredValue = findIndexOfKeyFromValue(packetLengthTempList, packetLengthOccuredMax)
print(f"\x1b[32m(\x1b[0m!\x1b[32m) \x1b[0mPacket Length \x1b[32m"+ str(packetLengthMaxOccuredValue).replace("{", "").replace("}", "")+" \x1b[0moccured \x1b[32m" + str(packetLengthOccuredMax) + " \x1b[0mtimes")

rawDataOccuredMax = max(rawDataTempList.values())
rawDataMaxOccuredValue = findIndexOfKeyFromValue(rawDataTempList, rawDataOccuredMax)



attackCertainty = 0
totalpackets = pcapLength
attackThreshold = 0.70

solution = ""

if (sourcePortOccuredMax / totalpackets) >= attackThreshold:
    amount = 1
    amount += (sourcePortOccuredMax / totalpackets)
    attackCertainty += amount
    solution += f"Block Source port {sourcePortMaxOccuredValue}\n"

if (destinationPortOccuredMax / totalpackets) >= attackThreshold:
    amount = 1
    amount += (destinationPortOccuredMax / totalpackets)
    attackCertainty += amount

if (sourceIPOccuredMax / totalpackets) >= attackThreshold:
    amount = 1
    amount += (sourceIPOccuredMax / totalpackets)
    attackCertainty += amount
    solution += f"Block Source IP {sourceIPMaxOccuredValue}\n"

if (packetLengthOccuredMax / totalpackets) >= attackThreshold:
    amount = 1
    amount += (packetLengthOccuredMax / totalpackets)
    attackCertainty += amount
    solution += f"Block Packet Length {packetLengthMaxOccuredValue}\n"

if (rawDataOccuredMax / totalpackets) >= attackThreshold:
    amount += 4
    solution += f"Block Hex String {rawDataMaxOccuredValue}\n"

if attackCertainty > 4:
	attackCertainty = 4

attackCertainty = round(attackCertainty, 2)

print(f"\n\x1b[0m     Attack Summary\x1b[0m")
if (attackCertainty/4) > attackThreshold:
	colorcode = "\x1b[31m"
else:
	colorcode = "\x1b[32m"

print(f"[{colorcode}!\x1b[0m] \x1b[0mAttack Certainty: {str(attackCertainty)}/4")

checkAttackIsKnownAmp(sourcePortMaxOccuredValue)

if "amp" not in attackType.lower():
	if (UDPCount / totalpackets) >= attackThreshold:
		attackType = "UDP"
	elif (TCPCount / totalpackets) >= attackThreshold:
		attackType = "TCP"
print("Suspected Attack Type: " + attackType)

if solution != "":
	steps = 0
	print("\n       Solution")
	for line in solution.split("\n"):
		if line != "":
			steps += 1
			print(f"\x1b[0m[\x1b[32m{steps}\x1b[0m] \x1b[0m{line}\x1b[0m")
