/**
 * Clever Relay – Google Apps Script (GAS) Relay
 *
 * This script acts as a "dumb pipe" between the local client (in Iran) and
 * the exit node (Clever Cloud). It performs ZERO processing on the encrypted
 * payload — it simply forwards HTTP POST bodies in both directions.
 *
 * IMPORTANT: All data is Base64-encoded by the client/server to prevent
 * corruption from getContentText()'s UTF-8 interpretation. This script
 * does NOT need to decode or encode anything — just forwards text as-is.
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
var RELAY_URL = "https://app-a6e79a9d-ddf5-49cd-a13a-ad8cee87456b.cleverapps.io/relay";

// ══════════════════════════════════════════════════════════════════════════════
// Utility: Case-Insensitive Header Reader
//
// HTTP headers may be lowercased by load balancers (e.g., Sōzu at Clever Cloud)
// or proxies. JavaScript's object property access is case-sensitive, so we must
// search headers case-insensitively to avoid undefined values.
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Reads an HTTP header value case-insensitively.
 *
 * @param {Object} headers - The headers object from response.getHeaders()
 * @param {string} name - The header name to search for (case-insensitive)
 * @returns {string} The header value, or empty string if not found
 */
function getHeaderCaseInsensitive(headers, name) {
  var lowerName = name.toLowerCase();
  for (var key in headers) {
    if (key.toLowerCase() === lowerName) {
      return headers[key];
    }
  }
  return '';
}

// ══════════════════════════════════════════════════════════════════════════════
// Main POST Handler
// ══════════════════════════════════════════════════════════════════════════════

/**
 * doPost receives encrypted tunnel traffic from the local client and
 * forwards it to the Clever Cloud exit node.
 *
 * The client sends Base64-encoded encrypted data in the POST body. This script
 * does not decrypt, inspect, or modify the data in any way — it is a pure relay.
 *
 * @param {Object} e - The event object from Apps Script
 * @returns {TextOutput} The exit node's response (Base64-encoded encrypted data)
 */
function doPost(e) {
  try {
    // ==========================================
    // Intelligent Router: if the client sends ?mode=batch,
    // delegate to the parallel fetchAll handler.
    // GAS always calls doPost() for every POST — doBatchPost
    // is never called directly by the runtime.
    // ==========================================
    if (e.parameter && e.parameter.mode === 'batch') {
      return doBatchPost(e);
    }

    var payload = e.postData.contents;

    // Build the request options
    var options = {
      'method': 'post',
      'payload': payload,
      'contentType': 'text/plain',
      'muteHttpExceptions': true,
      'followRedirects': true,
      'validateHttpsCertificates': true,
      // Timeout: GAS has a 60-second execution limit.
      // The exit node uses Time-Aware Preemption (45s) to stay within this.
    };

    // Forward any custom headers from the client
    var headers = {};
    if (e.parameter.cmd) {
      headers['X-Tunnel-Cmd'] = e.parameter.cmd;
    }

    if (Object.keys(headers).length > 0) {
      options['headers'] = headers;
    }

    // Forward to Clever Cloud
    var response = UrlFetchApp.fetch(RELAY_URL, options);

    // Read the response body (safe text — all data is Base64-encoded by the server)
    var responseText = response.getContentText();

    // Read the session status header case-insensitively.
    // Load balancers like Sōzu may lowercase headers (x-session-status).
    var respHeaders = response.getHeaders();
    var sessionStatus = getHeaderCaseInsensitive(respHeaders, 'X-Session-Status');

    // Build the response back to the client
    if (sessionStatus) {
      // Prepend status as a simple protocol: "STATUS=value\ndata"
      // The client parses this to detect HAS_MORE_DATA and CLOSED signals.
      return ContentService.createTextOutput(
        "STATUS=" + sessionStatus + "\n" + responseText
      ).setMimeType(ContentService.MimeType.TEXT);
    }

    return ContentService.createTextOutput(responseText)
      .setMimeType(ContentService.MimeType.TEXT);

  } catch (error) {
    // Log the error for debugging via Apps Script Logs
    Logger.log("Relay error: " + error.toString());

    // Return error info to the client so it can circuit-break this script
    return ContentService.createTextOutput(
      "STATUS=ERROR\n" + error.toString()
    ).setMimeType(ContentService.MimeType.TEXT);
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// Batch Mode with fetchAll (High-Performance Parallel Relay)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * doBatchPost handles batch mode. When the client sends multiple envelopes
 * packed into a JSON array, this function uses UrlFetchApp.fetchAll() to
 * fire them in parallel to the exit node.
 *
 * IMPORTANT: fetchAll() sends N separate HTTP requests to the exit node.
 * Each request is processed independently by the exit node's HTTP server
 * (not as a single batch). This is by design — Go's goroutines handle
 * the concurrency on the server side.
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
      return ContentService.createTextOutput("STATUS=ERROR\nEmpty batch")
        .setMimeType(ContentService.MimeType.TEXT);
    }

    // Build fetchAll request array — each envelope becomes a separate POST
    var requests = envelopes.map(function(envelope) {
      return {
        'url': RELAY_URL,
        'method': 'post',
        'payload': envelope,
        'contentType': 'text/plain',
        'muteHttpExceptions': true,
        'followRedirects': true,
        'validateHttpsCertificates': true,
      };
    });

    // Fire all requests in parallel!
    var responses = UrlFetchApp.fetchAll(requests);

    // Aggregate responses with case-insensitive header reading
    var results = responses.map(function(resp, index) {
      var respHeaders = resp.getHeaders();
      var status = getHeaderCaseInsensitive(respHeaders, 'X-Session-Status') || 'OK';
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
    ).setMimeType(ContentService.MimeType.TEXT);
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
