# Qualys-automation---VMAutomate
VMAutomate tool is used to automate Qualys Vulnerability management process by using Qualys API's. The script is written in python and uses multiple qualys APIs to perform the tasks. 
This comes handy when you want to store all of your qualys VM data in local sql database and perform flexile sql queries on the data to fulfill any kind of customised requirement/dashboard view.

The tool basically performs below mentioned activities :-
1. Report launching ,report fetching and storing report in sqlite database.
2. Fetching VM Scan lists details and storing it in database.
3. Fetching User account details and storing it in sqlite database.

Usage : script.py -h -u : Qualys Username -p : Qualys Password

Python 3.8 version

Modifications before script execution:
1. Qualys Client/Region specific API URL
2. Report template ID : Read qualys documentation for generating report template



