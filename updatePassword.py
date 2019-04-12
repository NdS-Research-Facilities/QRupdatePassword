#!/usr/bin/python

__author__ = 'nico@ndsrf.eu'
__support__ = 'nico@ndsrf.eu'

from ibm_qradar_lib import *
from ibm_password import *
from ibm_command_utils import *
from datetime import *; from dateutil.relativedelta import *
import sys, csv


def exportData(df):
	# '162,msrpctest,P50,bkcNvhioiEXfK0z0kc3L1g==,via2326'
	command = 'psql -U qradar -At -F , -c "select sd.id,sd.devicename,string_agg(cp.value::text,\',\' ORDER BY cp.name) from sensordevice sd, sensorprotocolconfigparameters cp where sd.devicetypeid=12 and sd.deviceenabled=true and sd.bulk_added=false and sd.spconfig=cp.sensorprotocolconfigid and cp.name in (\'UserName\',\'DomainName\',\'Password\') group by sd.id order by sd.id;"'
	results = executeCommand(command, log=False, noDebug=True)
	#print results
	records = len(results)-1
	print "Number of LogSources found for export: ", records
	with open(str(df),'wb') as csv_file:  # Python 2 version
		csv_writer = csv.writer(csv_file, dialect='excel', delimiter=',')
		csv_writer.writerow(['sid','name','domain','userid','password']) # write headers
		if results[0] == 0:
			donerecords = 0
			lastts = datetime.utcnow()
			for i in results[1::]:
				j=i.split(',')
				np=password_action('decrypt',j[3])[1]
				out=[j[0],j[1],j[2],j[4],np]
				csv_writer.writerow(out)

				nowts = datetime.utcnow()
				donerecords=donerecords+1
				x=relativedelta(nowts,lastts) * (records-donerecords)
				print str(donerecords)+" out of "+str(records)+" records done, time remaining (d:h:m:s) "+ str(int(x.days)) + ":"+str(int(x.hours))+":"+str(int(x.minutes))+":"+str(int(x.seconds))
				lastts=nowts


def updateData(df):
	#command = 'psql -U qradar -At -F , -c "select sd.id,sd.devicename,string_agg(cp.value::text,\',\') from sensordevice sd, sensorprotocolconfigparameters cp where sd.devicetypeid=12 and sd.deviceenabled=true and sd.bulk_added=false and sd.spconfig=cp.sensorprotocolconfigid and cp.name in (\'UserName\',\'DomainName\',\'Password\') group by sd.id order by sd.id"'
	#results = executeCommand(command, log=False, noDebug=True)
	#sid,name,domain,userid,password
	records = sum(1 for line in open(str(df)))-1
	print "Number of lines found for update: ", records
	with open(str(df),'rb') as csv_file:    # Python 2 version
		csv_reader = csv.reader(csv_file, dialect='excel', delimiter=',')
		next(csv_reader)

		lastts = datetime.utcnow()
		donerecords = 0
		for row in csv_reader:
			#  update name
			command = ('psql -U qradar -c "update sensordevice set devicename = \'%s\' where id = %s"' % (str(row[1]),str(row[0])))
			results = executeCommand(command, log=False, noDebug=True)
			# get spcid
			command = ('psql -U qradar -At -F , -c "select sd.spconfig from sensordevice sd where id = %s"' % (str(row[0])))
			results = executeCommand(command, log=False, noDebug=True)
			spconfigid = int(results[1])

			command = ('psql -U qradar -c "update sensorprotocolconfigparameters set value = \'%s\' where sensorprotocolconfigid = %s and name=\'DomainName\'; commit;"' % (str(row[2]), spconfigid ))
			results = executeCommand(command, log=False, noDebug=True)
			command = ('psql -U qradar -c "update sensorprotocolconfigparameters set value = \'%s\' where sensorprotocolconfigid = %s and name=\'UserName\'; commit;"' % (str(row[3]), spconfigid))
			results = executeCommand(command, log=False, noDebug=True)

			np = password_action('encrypt',str(row[4]))[1]
			command = ('psql -U qradar -c "update sensorprotocolconfigparameters set value = \'%s\' where sensorprotocolconfigid = %s and name=\'Password\'; commit;"' % (np, spconfigid))
			results = executeCommand(command, log=False, noDebug=True)
			command = ('psql -U qradar -c "update sensorprotocolconfigparameters set value = \'%s\' where sensorprotocolconfigid = %s and name=\'ConfirmPassword\'; commit;"' % (np, spconfigid))
			results = executeCommand(command, log=False, noDebug=True)

			nowts = datetime.utcnow()
			donerecords=donerecords+1
			x=relativedelta(nowts,lastts) * (records-donerecords)
			print str(donerecords)+" out of "+str(records)+" records done, time remaining (d:h:m:s) "+ str(int(x.days)) + ":"+str(int(x.hours))+":"+str(int(x.minutes))+":"+str(int(x.seconds))
			lastts=nowts


def main(action='help', dataFile=None):
		#print action, dataFile
		if action is "help":
			print "Usage: python updatePassword [OPTION] [FILE]"
			print "exports or updates (non-bulk) LogSources for \'Microsoft Windows Security Event Log over MSRPC\'"
			print ""
			print "This small utility must be run on a QRadar Console system."
			print "Versions tested: 7.3.2P0 "
			print ""
			print "Both [OPTION] and [FILE] are mandatory arguments"
			print "[OPTION] can either be:"
			print ""
			print "export"
			print ""
			print "	\"export\" option will create a .csv file provided by the filename [FILE] as a second argument."
			print "	the created file will include the LogSource ID, name, domain, userid and the unencrypted password"
			print ""
			print ""
			print "update"
			print ""
			print "	\"update\" option will read the file provided by the filename [FILE] and process the contents"
			print "	the input file should be a csv file with the following fields as a header line:"
			print "	lsid, name, domain, userid, unencryptedpassword"
			print "	(where lsid is the LogSource id number)"
			print ""
			print "Examples:"
			print "	python updatePasswords export outfile.csv"
			print "	python updatePasswords update outfile.csv"
			print ""
			print "Build April 2019 by Nico de Smidt, nico[at]ndsrf.eu"
			print "To report bugs, please create a report on https://github.com/NdS-Research-Facilities/QRupdatePassword"
			print ""


		elif action == "export":
			if isConsole():
				exportData(dataFile)
		elif action == "update":
			if isConsole():
				updateData(dataFile)

if len(sys.argv) == 3:
	print ""
	main(sys.argv[1],sys.argv[2])
else:
	main()
