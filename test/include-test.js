exports.includeTest = function(test){
	test.doesNotThrow(
	  function() {
	    var cares = require('../lib/cares.js');
	  },
	  Error,
	  'Failed to import cares.'
	);
	test.done();
};
