/*
 *  Created By: Roger L.
 *  Created Date: 1 Oct 2019
 *  Last Updated: 3 Oct 2019
 *  Purpose: Export XC report to csv
 *  Usage: node export-xc-report.js node  --serverURL http://localhost:8070 --u admin --p admin123 --appId app --reportId ba3631c176fa40f59c7f19225e853b27
 *  Output: ./output/component.csv, ./output/security.csv
 */

// Handle http request
const request = require('superagent');

// Query json
const jp = require('jsonpath');

// Read input arguments
const args = require('yargs').argv;

// Write to file
const write = require('write');

const appId = args.appId;
const reportId = args.reportId;
var serverURL = args.serverURL;
const userName = args.u;
const password = args.p;

// Text Constants
const CONTENT_TYPE = "Content-Type";
const APPLICATION_JSON = "application/json";
const CONSOLE_FONT_RED = "\x1b[31m%s\x1b[0m";
const LIST_IS_EMPTY = "This list is empty.";

// Assign default server URL
if (isInputEmpty(serverURL)) serverURL = "http://localhost:8070";

// Check if arguments exist and not empty (it is TRUE value when argument is empty)
if (isInputEmpty(appId) || isInputEmpty(reportId) || isInputEmpty(userName) || isInputEmpty(password)) {
    var errorMessage = "\n";
    if (isInputEmpty(appId)) errorMessage = "Missing argument: --appId\n";
    if (isInputEmpty(reportId)) errorMessage = "Missing argument: --reportId\n";
    if (isInputEmpty(userName)) errorMessage += "Missing argument: --u\n";
    if (isInputEmpty(password)) errorMessage += "Missing argument: --p\n";

    exitWithError(errorMessage);
}

eportXCReport(appId, reportId, serverURL, userName, password);

// Main function
function eportXCReport(appId, reportId, serverURL, userName, password) {
    // APIs to get json data
    const GET_BOM_API = serverURL + "/rest/report/" + appId + "/" + reportId + "/browseReport/bom.json";
    const GET_SECURITY_API = serverURL + "/rest/report/" + appId + "/" + reportId + "/browseReport/security.json";
    
    // 1. Get bom.json, convert to csv with headers: #, Component, Filename, Filepath
    request.get(GET_BOM_API).auth(userName, password).set(CONTENT_TYPE, APPLICATION_JSON)
        .then(response => {
            const body = response.body;

            // Get all components in the response body json
            const componentsArray = jp.query(body, '$.aaData.*');
            var csvOutput = "";

            // If the list is empty, write one-liner
            if (componentsArray.length == 0) {
                csvOutput = LIST_IS_EMPTY;
            } else {
                // For each component, extract data and export to csv
                var count = 0;

                // Set csv headers
                var csvOutput = "#,Component,Filepath\n";
                componentsArray.forEach(a => {
                    count++;
                    csvOutput += count + ","
                        + jp.query(a, '$..name').toString() + ","
                        + jp.query(a, '$..pathnames').toString() + "\n";
                    
                });
            }
    
            // Create output file (replace if already exist)
            write.sync('output/components.csv', csvOutput); 

            

        }).catch(error => {
            console.error(CONSOLE_FONT_RED, JSON.stringify(error, null, 2));
    });

    // 2. Get security.json, convert to csv with headers: #, Thread Level, Problem Code, Component, Filename, Link
    request.get(GET_SECURITY_API).auth(userName, password).set(CONTENT_TYPE, APPLICATION_JSON)
        .then(response => {
            const body = response.body;

            // Get all components in the response body json
            const componentsArray = jp.query(body, '$.aaData.*');
            var csvOutput = "";

            // If the list is empty, write one-liner
            if (componentsArray.length == 0) {
                csvOutput = LIST_IS_EMPTY;
            } else {

                // For each component, extract data and export to csv
                var count = 0;

                // Set csv headers
                csvOutput = "#,Thread Level,Problem Code,Component,Link\n"
                componentsArray.forEach(a => {
                    count++;
                    csvOutput += count + ","
                        + jp.query(a, '$..score').toString() + ","  // CVSS Score
                        + jp.query(a, '$..reference').toString() + ","  // CVE number
                        + jp.query(a, '$..name').toString() + ","  // component name and version
                        + jp.query(a, '$..url').toString() + "\n";  // Link to cve website
                });
            }

            // Create output file (replace if already exist)
            write.sync('output/security.csv', csvOutput); 

        }).catch(error => {
            console.error(CONSOLE_FONT_RED, JSON.stringify(error, null, 2));
    });
}

// Utility functions
// Check if input argument is empty
function isInputEmpty(input) {
    return (input === undefined || typeof (input) === "boolean");
}

function exitWithError(message) {
    // Print error message in red
    console.error(CONSOLE_FONT_RED, message);
    // Exit with error code
    process.exit(1);
}
