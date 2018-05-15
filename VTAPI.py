from __future__ import division
import virustotal
import pandas
import time
from xlrd import open_workbook
from xlutils.copy import copy
# may need to import to your system using pip
# Python version 2.7

# Ltango
# 4-26-2018

# Should private key be obtained need to change the key and remove or reduce the sleep timer 
# be careful that column is hard coded for xls (column 10[J]) and 
# will overwrite any data put in that column

# This code takes any number xls files from a directory, reads in hash values from the
# column labeled 'id', sends those hash values to the virus total api to be checked
# the report is then read and this takes the percentage of reports with malware related responses
# over the total number or responses and writes that assessment along with the number of
# malware responses/total and writes that into column 'J' (tenth column) of that same xls file
# if the file hash is not found within virus total then UNKNOWN is written 
#
# example:
# CLEAN 0/70
# UNKNOWN
# HIGH 47/65
# LOW 1/69
#
# note: using xlsx or any other extension will not work but can be done with different libraries
# for this code only use xls files

# VirusTotal API public key
apiKey = 'your_api_key'
v = virustotal.VirusTotal(apiKey)

#Enter file path of xls files<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
filepath = R"C:\Users\user\Documents\\"

#Enter any number of xls files within the directory to be modified<<<<<<<<<<<<<<<<
excelFile = ['example.xls']

#Don't touch these
totalCount = 0
malwareCount = 0
rowCount = 1

#change these values to change what is flagged as LOW and MEDIUM and HIGH
LOWPERCENTAGERISK = .05
MEDPERCENTAGERISK = .10

#change this value to change which column xls writes to (9 = J)
columnToWriteTo = 9

#change this value to change sleep time between file has checks
hashCheckSleepTime = 15

#Scan each xls file
for k in range(0,len(excelFile)):
	print('')
	print('Retreiving ' + excelFile[k])
	print('')

	try:
		#read in entire xls file 
		df = pandas.read_excel(filepath + excelFile[k])
		values = df['id'].values
		rb = open_workbook(filepath + excelFile[k])
		rowCount = 1
		print('Sucess!!!')
		print('')

	except:
		print('failed to retrieve file ' + excelFile[k])
		print('')
		continue
	#Scan every line in xls files
	for i in values:
		try:
			#Read id from excel file
			report = v.get(i) 
			
			#wait for report to finish
			report.join()
			assert report.done == True
		except:
			#type into excel UNKNONWN
			#TODO write this as a method so its not used so many times
			rb = open_workbook(filepath + excelFile[k])
			wb = copy(rb)
			s = wb.get_sheet(0)
			s.write(rowCount,columnToWriteTo,'UNKNOWN')
			wb.save(filepath + excelFile[k])

			totalCount = 0
			malwareCount = 0
			rowCount = rowCount + 1
			print('VirusTotal cannot find file hash... ' + i + ' is UKNOWN risk')
			print('waiting 15 seconds... VirusTotal Public API only supports 4 calls per minute...')
			time.sleep(15)
			continue

		for antivirus, malware in report:
			if malware is not None:
				malwareCount = malwareCount + 1
				totalCount = totalCount + 1
				
			else:
				totalCount = totalCount + 1
				
				
		#VirusTotal Public API only 4 calls per minute
		print(i + " has a VirusTotal Count of " + str(malwareCount) + "/" + str(totalCount))
		if malwareCount == 0:
			print(i + " is CLEAN")
			#write to excel CLEAN
			#TODO write this as a method so its not used so many times
			rb = open_workbook(filepath + excelFile[k])
			wb = copy(rb)
			s = wb.get_sheet(0)
			s.write(rowCount,columnToWriteTo,'CLEAN ' + str(malwareCount) + "/" + str(totalCount))
			wb.save(filepath + excelFile[k])

		elif (malwareCount/totalCount) < LOWPERCENTAGERISK:
			print(i + " is LOW risk")
			#write to excel LOW
			#TODO write this as a method so its not used so many times
			rb = open_workbook(filepath + excelFile[k])
			wb = copy(rb)
			s = wb.get_sheet(0)
			s.write(rowCount,columnToWriteTo,'LOW ' + str(malwareCount) + "/" + str(totalCount) )
			wb.save(filepath + excelFile[k])

		elif (malwareCount/totalCount) < MEDPERCENTAGERISK:
			print(i + " is MED risk")
			#write to excel MEDIUM
			#TODO write this as a method so its not used so many times
			rb = open_workbook(filepath + excelFile[k])
			wb = copy(rb)
			s = wb.get_sheet(0)
			s.write(rowCount,columnToWriteTo,'MEDIUM ' + str(malwareCount) + "/" + str(totalCount))
			wb.save(filepath + excelFile[k])
		else:
			print(i + " is HIGH risk")
			#write to excel HIGH
			#TODO write this as a method so its not used so many times
			rb = open_workbook(filepath + excelFile[k])
			wb = copy(rb)
			s = wb.get_sheet(0)
			s.write(rowCount,columnToWriteTo,'HIGH ' + str(malwareCount) + "/" + str(totalCount))
			wb.save(filepath + excelFile[k])

		#reset counters for next iteration of checking file hash
		totalCount = 0
		malwareCount = 0
		print('waiting ' + hashCheckSleepTime +' seconds... VirusTotal Public API only supports 4 calls per minute...')
		time.sleep(hashCheckSleepTime)
		rowCount = rowCount + 1

	print("finished modifying " + excelFile[k])
	print('')

print('ALL DONE')
