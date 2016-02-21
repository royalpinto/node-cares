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

    resolve4: function (test) {
        this.resolver.resolve4('www.google.com', function (err, response) {
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

    resolve6: function (test) {
        this.resolver.resolve6('ipv6.google.com', function (err, response) {
            test.strictEqual(err, null, err);
            test.notStrictEqual(response, null, err);
            test.ok(response instanceof Array, "Invalid response returned.");
            test.ok(response.length > 0, "Invalid response returned.");
            response.forEach(function (ip) {
                test.ok(net.isIP(ip), "Invalid IP address.");
                test.ok(net.isIPv6(ip), "Invalid IP address.");
            });
            test.done();
        });
    },

    lookup: function (test) {
        this.resolver.lookup('www.google.com', function (err, ip) {
            test.strictEqual(err, null, err);
            test.notStrictEqual(ip, null, err);
            test.ok(net.isIP(ip), "Invalid IP address.");
            test.done();
        });
    },

};
