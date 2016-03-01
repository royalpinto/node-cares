// Copyright 2016 Lohith Royal Pinto <royalpinto@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE


var cares = require('../lib/cares.js');
var net = require('net');
var SERVERS = ['127.0.0.1'];
var PORT = 8080;


module.exports = {

    setUp: function (callback) {
        this.resolver = new cares.Resolver({
            servers: SERVERS,
            udp_port: PORT,
        });
        callback();
    },
    tearDown: function (callback) {
        callback();
    },

    resolve: function (test) {
        this.resolver.resolve('www.something.com', function (err, response) {
            test.ifError(err);
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
        this.resolver.resolve4('www.something.com', function (err, response) {
            test.ifError(err);
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
        this.resolver.resolve6('ipv6.something.com', function (err, response) {
            test.ifError(err);
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
        this.resolver.lookup('www.google.com', function (err, ip, family) {
            test.ifError(err);
            test.notStrictEqual(ip, null, err);
            test.ok(net.isIP(ip), "Invalid IP address.");
            if (family === 4) {
                test.strictEqual(family, 4);
                test.ok(net.isIPv4(ip), "Invalid IP address.");
            } else if (family === 6) {
                test.strictEqual(family, 6);
                test.ok(net.isIPv6(ip), "Invalid IP address.");
            } else {
                test.ok(false, "Invalid family found.");
            }
            test.done();
        });
    },

};
