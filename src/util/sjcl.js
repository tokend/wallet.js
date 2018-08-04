var sjcl = require('sjcl');
require('sjcl-scrypt').extendSjcl(sjcl);

var randomWords = sjcl.random.randomWords;

sjcl.random.randomWords = function(nwords) {
  if (!sjcl.random.isReady()) {
    for (var i = 0; i < 8; i++) {
      sjcl.random.addEntropy(Math.random(), 32, "Math.random()");
    }

    if (!sjcl.random.isReady()) {
      throw "Unable to seed sjcl entropy pool";
    }
  }

  return randomWords.call(sjcl.random, nwords);
};

module.exports = sjcl;