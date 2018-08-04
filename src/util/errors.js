'use strict';

var util = require("util");

Error.subclass = function(errorName, statusCode) {
  var newError = function(message, meta) {
    this.name    = errorName;
    this.code    = statusCode;
    this.message = (message || "");
    this.meta = meta || {}
  };

  newError.subclass = this.subclass;
  util.inherits(newError, this);

  return newError;
};

var errors = module.exports;

errors.DataCorrupt = Error.subclass('DataCorrupt');

