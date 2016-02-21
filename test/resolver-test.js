var cares = require('../lib/cares.js');
var net = require('net');


module.exports = {

    setUp: function (callback) {
        this.resolver = new cares.Resolver({
            servers: ['8.8.8.8'],
        });
        callback();
    },
    tearDown: function (callback) {
        callback();
    },

    resolve: function (test) {
        this.resolver.resolve('www.google.com', function (err, response) {
            test.strictEqual(err, null, err);
            test.notStrictEqual(response, null, err);
            test.ok(response instanceof Array, "Invalid response returned.");
            test.ok(response.length > 0, "Invalid response returned.");
            response.forEach(function (ip) {
                test.ok(net.isIP(ip), "Invalid IP address.");
                test.ok(net.isIPv4(ip), "Invalid IP address.");
            });
            test.done();
        });
    },
};
