#!/bin/bash

#
#   Created By: Bryan Whyte
#   Created Date: Feb 12 2020
#   Last Updated: Feb 12 2020
#   Purpose: Automate steps to leverage Roger Lau's script "export-xc-lc.js". 
#

IQ="http://localhost:8070"
CLI="/opt/sonatype/iq-1.80/nexus-iq-cli-1.80.0-01.jar"
STAGE="build"    # develop|build|stage-release|release|operate
USER="admin"
PWD='admin123'
APP_NAME="scripttest"
APP_DIR="/Users/bryanwhyte/git/php-sample-app/"

#Execute XC Scan
read XC_SCAN_ID <<< $(java -jar $CLI -xc -s $IQ -t $STAGE -a $USER':'$PWD -i $APP_NAME $APP_DIR | awk -F 'Assigned scan ID' '{print $2}' | awk '{print $1}')
echo XC Assigned Scan ID: "$XC_SCAN_ID"

#Convert XC data to LC Report
node export-xc-lc.js -serverURL $IQ --u $USER --p $PWD --appId $APP_NAME --reportId $XC_SCAN_ID

#Move LC Format of data to root of app scanned
mv output/xc-report-bom.xml $APP_DIR

#Execute LC Scan
java -jar $CLI -s $IQ -t $STAGE -a $USER':'$PWD -i $APP_NAME $APP_DIR
