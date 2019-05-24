"use strict";
// =================================================================
//          #     #                 #     #
//          ##    #   ####   #####  ##    #  ######   #####
//          # #   #  #    #  #    # # #   #  #          #
//          #  #  #  #    #  #    # #  #  #  #####      #
//          #   # #  #    #  #####  #   # #  #          #
//          #    ##  #    #  #   #  #    ##  #          #
//          #     #   ####   #    # #     #  ######     #
//
//       ---   The NorNet Testbed for Multi-Homed Systems  ---
//                       https://www.nntb.no
// =================================================================
//
// Container-based Speed Test for NorNet Edge
//
// Copyright (C) 2018-2019 by Thomas Dreibholz
// Copyright (C) 2012-2017 by Džiugas Baltrūnas
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Contact: dreibh@simula.no


var page   = require("webpage").create();
var system = require("system");
var address;
var output;
var req;


// ###### Generic Functions #################################################

// ====== Print error =======================================================
console.error = function () {
  require("system").stderr.write(Array.prototype.join.call(arguments, " ") + "\n");
};


// ====== Callback for error ================================================
phantom.onError = function(msg, trace) {
  var msgStack = ["PHANTOM ERROR: " + msg];
  if (trace && trace.length) {
    msgStack.push("TRACE:");
    trace.forEach(function(t) {
      msgStack.push(" -> " + (t.file || t.sourceURL) + ": " +
                    t.line + (t.function ?
                                 " (in function \"" + t.function +"\")" : ""));
    });
  }
  req.phantomError = msgStack.join("\n");
};


// ###### Resource Handling Functions #######################################

// ====== Callback for resource requested ===================================
page.onResourceRequested = function(request) {
  req.res[request.id] = {
    method: request.method,
    url: request.url.substring(0, 64),
    requestTime: request.time
  };
};


// ====== Callback for resource received ====================================
page.onResourceReceived = function(response) {
  req.res[response.id].responseTime   = response.time;
  req.res[response.id].responseStatus = response.status;
  req.res[response.id].duration =
     response.time.getTime() - req.res[response.id].requestTime.getTime();
};


// ====== Callback for resource error =======================================
page.onResourceError = function(resourceError) {
  req.res[resourceError.id].resourceErrorCode   = resourceError.errorCode;
  req.res[resourceError.id].resourceErrorString = resourceError.errorString;
};


// ====== Callback for resource timeout =====================================
page.onResourceTimeout = function(request) {
  req.res[request.id].resourceTimeout = true;
};


// ====== Callback for error ================================================
page.onError = function(msg, trace) {
  var msgStack = ["ERROR: " + msg];
  if (trace && trace.length) {
    msgStack.push("TRACE:");
    trace.forEach(function(t) {
      msgStack.push(" -> " + t.file + ": " +
                    t.line + (t.function ?
                                 " (in function \"" + t.function +"\")" : ""));
    });
  }
  if (typeof req.pageError === "undefined" || req.pageError === null) {
    req.pageError = [];
  }
  req.pageError[req.pageError.length] = msgStack.join("\n");
};


// ====== Callback for loading started ======================================
page.onLoadStarted = function() {
  req.startTime = new Date();
};


// ###### Load Website ######################################################

// ====== Check argument ====================================================
if (system.args.length === 1) {
  console.error("Usage: loadspeed.js URL");
  phantom.exit();
}
address = system.args[1];

// ====== Configuration =====================================================
// iPhone 6
page.settings.userAgent       = "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A456 Safari/602.1";
page.viewportSize             = { width: 750, height: 1334 };
page.settings.resourceTimeout = 30000;

req = {
  "startTime": null,
  "status":    null,
  "res":       {}
};

// ====== Load website ======================================================
page.open(address, function(status) {
   var now = new Date();
   try {
      req.endTime  = now;
      req.duration = now.getTime() - req.startTime.getTime();
      req.status   = status;
//       if (status !== "success") {
//          // ...
//       } else {
//          // ...
//       }
   } catch (err) {
      req.status       = "exception";
      req.errorName    = err.name;
      req.errorMessage = err.message;
   }
   finally {
      window.setTimeout(function () {
         Date.prototype.toJSON = function() { return this.toISOString().replace(/T/, " ").replace(/Z/, ""); };
         console.log("BEGIN-JSON");
         console.log(JSON.stringify(req, null, "\t"));
         console.log("END-JSON");
         phantom.exit(0);
      }, 1000);
   }
});
