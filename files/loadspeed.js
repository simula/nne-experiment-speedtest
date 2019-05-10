var page = require('webpage').create(),
    system = require('system'),
    address, output, req;

console.error = function () {
  require("system").stderr.write(Array.prototype.join.call(arguments, ' ') + '\n');
};

if (system.args.length === 1) {
  console.error('Usage: loadspeed.js <some URL>');
  phantom.exit();
}

phantom.onError = function(msg, trace) {
  var msgStack = ['PHANTOM ERROR: ' + msg];
  if (trace && trace.length) {
    msgStack.push('TRACE:');
    trace.forEach(function(t) {
      msgStack.push(' -> ' + (t.file || t.sourceURL) + ': ' + t.line + (t.function ? ' (in function ' + t.function +')' : ''));
    });
  }
  req['phantomError'] = msgStack.join('\n');
};

page.onResourceRequested = function(request) {
  req['res'][request.id] = {
    method: request.method,
    url: request.url.substring(0, 64),
    requestTime: request.time,
  };
};

page.onResourceReceived = function(response) {
  req['res'][response.id].responseTime = response.time; 
  req['res'][response.id].responseStatus = response.status;
  req['res'][response.id].duration = response.time.getTime() - req['res'][response.id].requestTime.getTime();
};

page.onResourceError = function(resourceError) {
  req['res'][resourceError.id].resourceErrorCode = resourceError.errorCode;
  req['res'][resourceError.id].resourceErrorString = resourceError.errorString;
};

page.onError = function(msg, trace) {
  var msgStack = ['ERROR: ' + msg];
  if (trace && trace.length) {
    msgStack.push('TRACE:');
    trace.forEach(function(t) {
      msgStack.push(' -> ' + t.file + ': ' + t.line + (t.function ? ' (in function "' + t.function +'")' : ''));
    });
  }
  if (typeof req['pageError'] === 'undefined' || req['pageError'] === null) {
    req['pageError'] = new Array();
  }
  req['pageError'][req['pageError'].length] = msgStack.join('\n');
};

page.onResourceTimeout = function(request) {
  req['res'][request.id].resourceTimeout = true;
};

page.onLoadStarted = function() {
  req['startTime'] = new Date();
};

address = system.args[1];
// iPhone 6
page.settings.userAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A456 Safari/602.1';
page.viewportSize = { width: 750, height: 1334 };
page.settings.resourceTimeout = 30000;

req = {
  'startTime': null,
  'status': null,
  'res': {},
};

page.open(address, function(status) {
  var now = new Date();
  try {
    req['endTime'] = now;
    req['duration'] = now.getTime() - req.startTime.getTime();
    req['status'] = status;
    if (status !== 'success') {
      // ...
    } else {
      // ...
    }
  } catch (err) {
    req.status = 'exception';
    req.errorName = err.name;
    req.errorMessage = err.message;
  } finally {
    window.setTimeout(function () {
      Date.prototype.toJSON = function() { return this.toISOString().replace(/T/, ' ').replace(/Z/, '') }
      console.log(JSON.stringify(req, undefined, null));
      phantom.exit();
    }, 1000);
  }

});
