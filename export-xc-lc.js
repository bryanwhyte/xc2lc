/*
 *  Created By: Roger L.
 *  Created Date: 22 Nov 2019
 *  Last Updated: 26 Nov 2019
 *  Purpose: Export XC report to xc-report-bom.xml for ingestion to LC report. Part of the file name, xc-report, will be used as identifcation source.
 *  Usage: node export-xc-lc.js node  --serverURL http://localhost:8070 --u admin --p admin123 --appId app --reportId ba3631c176fa40f59c7f19225e853b27
 *  Output: ./output/xc-report-bom.xml
 */

// Handle http request
const request = require('superagent');

// Query json
const jp = require('jsonpath');

// Build xml output
const xmlbuilder = require('xmlbuilder');

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

    // 1. Get bom.json
    request.get(GET_BOM_API).auth(userName, password).set(CONTENT_TYPE, APPLICATION_JSON)
        .then(bomResponse => {
            const bomJson = bomResponse.body;

            // 2. Get security.json
            request.get(GET_SECURITY_API).auth(userName, password).set(CONTENT_TYPE, APPLICATION_JSON)
                .then(securityResponse => {
                    const securityJson = securityResponse.body;

                    // Get all components in the response body json
                    var componentsArray = jp.query(bomJson, '$.aaData.*');

                    // Setting the ground for the xml output file. Components and vulnerabilities to be added below.
                    var outputJson = {
                        'bom': {
                            '@serialNumber': 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79',
                            '@version': '1',
                            '@xmlns': 'http://cyclonedx.org/schema/bom/1.1',
                            '@xmlns:v': 'http://cyclonedx.org/schema/ext/vulnerability/1.0',
                            'components': { 'component': [] }
                        }
                    };

                    // If the list is empty, write one-liner
                    if (componentsArray.length == 0) {
                        outputJson = LIST_IS_EMPTY;
                    } else {
                        _getComponentAndVuln(componentsArray, outputJson);  // Pass array and json as reference. Fill up outputJson.
                    }

                    // Get all components with security vulnerabilites
                    var vulnsArray = jp.query(securityJson, '$.aaData.*');

                    if (vulnsArray.length > 0) {
                        _getComponentAndVuln(vulnsArray, outputJson);
                    }

                    // 3. Create xml output file (replace if already exist) in human readable format.
                    var outputXml = xmlbuilder.create(outputJson, { encoding: 'utf-8' }).end({ pretty: true });
                    //console.log(outputXml);
                    write.sync('output/xc-report-bom.xml', outputXml);

                }).catch(error => { console.error(CONSOLE_FONT_RED, JSON.stringify(error, null, 2)); });
        }).catch(error => { console.error(CONSOLE_FONT_RED, JSON.stringify(error, null, 2)); });
}

// Function to get component and vulnerabilities information from componentArray. Fill up outputJson.
function _getComponentAndVuln(componentsArray, outputJson) {
    componentsArray.forEach((value) => {
        var componentSplit = jp.query(value, '$..name').toString().split(":");
        var componentName = componentSplit[0] === undefined ? "" : componentSplit[0];  // Component name
        var componentVersion = componentSplit[1] === undefined ? "-" : componentSplit[1];  // Component version. Putting "-" because component without version is omitted.
        var cveNumber = jp.query(value, '$..reference').toString();  // CVE number

        // Get component information
        var componentJson = {
            '@type': 'library',  // Always the same value. @ for attributes. Refer to xmlbuilder github.
            'name': componentName,
            'version': componentVersion,
            'purl': 'pkg:php/' + componentName + '@' + componentVersion,
            'v:vulnerabilities': { 'v:vulnerability': [] }
        };

        // Get vulnerability information, only if there is a CVE number attached to it.
        if (cveNumber.length > 0) {
            var vuln = _getVulnJson(value);
            componentJson['v:vulnerabilities']['v:vulnerability'].push(vuln);
        }

        outputJson.bom.components.component.push(componentJson);

    });

}

function _getVulnJson(value) {
    var vuln = {
        'v:id': jp.query(value, '$..reference').toString(),  // CVE number
        'v:source': {
            '@name': jp.query(value, '$..source').toString(),  // Source, e.g., cve
            'v:url': jp.query(value, '$..url').toString()  // Link to cve website
        },
        'v:ratings': [{
            'v:rating': {
                'v:score': {
                    'v:base': jp.query(value, '$..score').toString()  // CVSS Score
                }
            }
        }],
        'v:description': 'Imported from XC report using custom script. Expect some sections to be blank. For more details about this vulnerability, click on the link under ISSUE on the left.',
    };

    return vuln;
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
