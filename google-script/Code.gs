/**
 * Clever Relay – Google Apps Script (GAS) Relay
 *
 * This script acts as a "dumb pipe" between the local client (in Iran) and
 * the exit node (Clever Cloud). It performs ZERO processing on the encrypted
 * payload — it simply forwards HTTP POST bodies in both directions.
 *
 * Deployment:
 * 1. Go to https://script.google.com
 * 2. Create a new project, paste this code
 * 3. Deploy as Web App (Execute as: Me, Access: Anyone)
 * 4. Copy the deployment URL and add it to your client's GAS pool
 *
 * Important:
 * - Set RELAY_URL to your Clever Cloud app URL
 * - muteHttpExceptions=true prevents the script from crashing on server errors
 * - The script supports both single packet and batch (fetchAll) relay modes
 */

// ══════════════════════════════════════════════════════════════════════════════
// Configuration
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Your Clever Cloud exit node URL.
 * Change this to your actual deployment URL.
 */
var RELAY_URL = "https://your-app.cleverapps.io/relay";

// ══════════════════════════════════════════════════════════════════════════════
// Main POST Handler
// ══════════════════════════════════════════════════════════════════════════════

/**
 * doPost receives encrypted tunnel traffic from the local client and
 * forwards it to the Clever Cloud exit node.
 *
 * The client sends encrypted binary data in the POST body. This script
 * does not decrypt, inspect, or modify the data in any way.
 *
 * Supports two modes:
 * 1. Single relay: One encrypted envelope → forwarded as-is
 * 2. Batch relay: Multiple envelopes → forwarded with X-Batch header
 *
 * @param {Object} e - The event object from Apps Script
 * @returns {TextOutput} The exit node's response (encrypted)
 */
function doPost(e) {
  try {
    var payload = e.postData.contents;
    var isBatch = e.parameter.batch === "1";

    // Build the request options
    var options = {
      'method': 'post',
      'payload': payload,
      'contentType': 'application/octet-stream',
      'muteHttpExceptions': true,
      'followRedirects': true,
      'validateHttpsCertificates': true,
      // Timeout: GAS has a 60-second execution limit.
      // The exit node uses Time-Aware Preemption (45s) to stay within this.
    };

    // Add batch header if needed
    var headers = {};
    if (isBatch) {
      headers['X-Batch'] = '1';
    }

    // Forward any custom headers from the client
    if (e.parameter.cmd) {
      headers['X-Tunnel-Cmd'] = e.parameter.cmd;
    }

    if (Object.keys(headers).length > 0) {
      options['headers'] = headers;
    }

    // Forward to Clever Cloud
    var response = UrlFetchApp.fetch(RELAY_URL, options);

    // Build the response back to the client
    var output = ContentService.createTextOutput(response.getContentText());
    output.setMimeType(ContentService.MimeType.TEXT);

    // Preserve the session status header from the exit node
    // Note: GAS cannot set custom response headers, so we encode
    // the status in the response body prefix.
    var sessionStatus = response.getHeaders()['X-Session-Status'] || '';
    if (sessionStatus) {
      // Prepend status as a simple protocol: "STATUS:data"
      output = ContentService.createTextOutput(
        "STATUS=" + sessionStatus + "\n" + response.getContentText()
      );
    }

    return output;

  } catch (error) {
    // Log the error for debugging via Apps Script Logs
    Logger.log("Relay error: " + error.toString());

    // Return error info to the client so it can circuit-break this script
    return ContentService.createTextOutput(
      "STATUS=ERROR\n" + error.toString()
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Batch Mode with fetchAll (High-Performance Parallel Relay)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * doPost handler for batch mode. When the client sends multiple envelopes
 * packed into a JSON array, this function uses UrlFetchApp.fetchAll() to
 * fire them in parallel to the exit node.
 *
 * The client activates this mode by sending:
 *   POST ?mode=batch
 *   Body: JSON array of Base64-encoded envelopes
 *
 * @param {Object} e - The event object
 * @returns {TextOutput} Aggregated responses
 */
function doBatchPost(e) {
  try {
    var envelopes = JSON.parse(e.postData.contents);

    if (!Array.isArray(envelopes) || envelopes.length === 0) {
      return ContentService.createTextOutput("STATUS=ERROR\nEmpty batch");
    }

    // Build fetchAll request array
    var requests = envelopes.map(function(envelope) {
      return {
        'url': RELAY_URL,
        'method': 'post',
        'payload': envelope,
        'contentType': 'application/octet-stream',
        'muteHttpExceptions': true,
        'followRedirects': true,
        'validateHttpsCertificates': true,
      };
    });

    // Fire all requests in parallel!
    var responses = UrlFetchApp.fetchAll(requests);

    // Aggregate responses
    var results = responses.map(function(resp, index) {
      var status = resp.getHeaders()['X-Session-Status'] || 'OK';
      return {
        'index': index,
        'status': status,
        'code': resp.getResponseCode(),
        'data': resp.getContentText(),
      };
    });

    return ContentService.createTextOutput(JSON.stringify(results))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    Logger.log("Batch relay error: " + error.toString());
    return ContentService.createTextOutput(
      "STATUS=ERROR\n" + error.toString()
    );
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Health Check (GET handler)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * doGet provides a simple health check endpoint. The client can periodically
 * GET the script URL to measure latency and verify the script is alive.
 *
 * @param {Object} e - The event object
 * @returns {TextOutput} Health status
 */
function doGet(e) {
  var result = {
    'status': 'ok',
    'relay_url': RELAY_URL,
    'timestamp': new Date().toISOString(),
    'quota': getQuotaInfo(),
  };

  return ContentService.createTextOutput(JSON.stringify(result))
    .setMimeType(ContentService.MimeType.JSON);
}

// ══════════════════════════════════════════════════════════════════════════════
// Utility Functions
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Returns approximate quota information for this script.
 * Useful for the client's Circuit Breaker to know when a script is near
 * its daily limit.
 */
function getQuotaInfo() {
  try {
    // UrlFetchApp daily quota: 20,000 calls for free accounts
    // We can't directly query remaining quota, but we can track usage
    var props = PropertiesService.getScriptProperties();
    var today = new Date().toISOString().split('T')[0];
    var key = 'calls_' + today;
    var calls = parseInt(props.getProperty(key) || '0', 10);

    // Increment the counter
    props.setProperty(key, String(calls + 1));

    return {
      'calls_today': calls + 1,
      'limit': 20000,
      'remaining': Math.max(0, 20000 - calls - 1),
    };
  } catch (e) {
    return { 'calls_today': -1, 'limit': 20000, 'remaining': -1 };
  }
}
