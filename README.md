# VirusTotal-API
Some Python VirusTotal API requests - reads file hashes from and edits xls files


Should private key be obtained need to change the key and remove or reduce the sleep timer 
be careful that column is hard coded for xls (column 10[J]) and 
will overwrite any data put in that column

This code takes any number xls files from a directory, reads in hash values from the
column labeled 'id', sends those hash values to the virus total api to be checked
the report is then read and this takes the percentage of reports with malware related responses
over the total number or responses and writes that assessment along with the number of
malware responses/total and writes that into column 'J' (tenth column) of that same xls file
if the file hash is not found within virus total then UNKNOWN is written 
