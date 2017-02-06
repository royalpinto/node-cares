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
var chai = require('chai');
var net = require('net');

var SERVERS = ['127.0.0.1'];
var PORT = 8080;
var server = require('./setup/dummydns.js');
var dnsentries = require('./setup/dnsentries.js');


describe('Resolver', function() {
    var resolver;

    before(function(done) {
        server.on('listening', function() {
            resolver = new cares.Resolver({
                servers: SERVERS,
                /* eslint-disable camelcase */
                udp_port: PORT,
                /* eslint-enable */
            });
            done();
        });
        server.serve(PORT);
    });

    after(function(done) {
        done();
    });

    it('should resolve', function(done) {
        resolver.resolve('www.something.com', function(err, response) {
            chai.expect(err).to.be.equal(null);
            chai.assert.isArray(response);
            chai.expect(response).to.have.length.of.at.least(1);
            response.forEach(function(ip) {
                chai.expect(net.isIP(ip)).to.be.ok;
                chai.expect(net.isIPv4(ip)).to.be.ok;
            });

            var expected = (
                dnsentries[cares.NS_C_IN][cares.NS_T_A]['www.something.com']
                .answer
            )
            .filter(function(answer) {
                return answer.type === cares.NS_T_A;
            })
            .map(function(answer) {
                return answer.address;
            });

            chai.expect(response).to.have.lengthOf(expected.length);

            response.forEach(function(answer, index) {
                chai.expect(answer).to.deep.equal(expected[index]);
            });

            done();
        });
    });

    it('should resolve A', function(done) {
        resolver.resolve('www.something.com', 'A', function(err, response) {
            chai.expect(err).to.be.equal(null);
            chai.assert.isArray(response);
            chai.expect(response).to.have.length.of.at.least(1);
            response.forEach(function(ip) {
                chai.expect(net.isIP(ip)).to.be.ok;
                chai.expect(net.isIPv4(ip)).to.be.ok;
            });

            var expected = (
                dnsentries[cares.NS_C_IN][cares.NS_T_A]['www.something.com']
                .answer
            )
            .filter(function(answer) {
                return answer.type === cares.NS_T_A;
            })
            .map(function(answer) {
                return answer.address;
            });

            chai.expect(response).to.have.lengthOf(expected.length);

            response.forEach(function(answer, index) {
                chai.expect(answer).to.deep.equal(expected[index]);
            });

            done();
        });
    });

    it('should resolve AAAA', function(done) {
        resolver.resolve('www.something.com', 'AAAA', function(err, response) {
            chai.expect(err).to.be.equal(null);
            chai.assert.isArray(response);
            chai.expect(response).to.have.length.of.at.least(1);
            response.forEach(function(ip) {
                chai.expect(net.isIP(ip)).to.be.ok;
                chai.expect(net.isIPv6(ip)).to.be.ok;
            });

            var expected = (
                dnsentries[cares.NS_C_IN][cares.NS_T_AAAA]['www.something.com']
                .answer
            )
            .filter(function(answer) {
                return answer.type === cares.NS_T_AAAA;
            })
            .map(function(answer) {
                return answer.address;
            });

            chai.expect(response).to.have.lengthOf(expected.length);

            response.forEach(function(answer, index) {
                chai.expect(answer).to.deep.equal(expected[index]);
            });

            done();
        });
    });

    it('should resolve 4', function(done) {
        resolver.resolve4('www.something.com', function(err, response) {
            chai.expect(err).to.be.equal(null);
            chai.assert.isArray(response);
            chai.expect(response).to.have.length.of.at.least(1);
            response.forEach(function(ip) {
                chai.expect(net.isIP(ip)).to.be.ok;
                chai.expect(net.isIPv4(ip)).to.be.ok;
            });

            var expected = (
                dnsentries[cares.NS_C_IN][cares.NS_T_A]['www.something.com']
                .answer
            )
            .filter(function(answer) {
                return answer.type === cares.NS_T_A;
            })
            .map(function(answer) {
                return answer.address;
            });

            chai.expect(response).to.have.lengthOf(expected.length);

            response.forEach(function(answer, index) {
                chai.expect(answer).to.deep.equal(expected[index]);
            });

            done();
        });
    });

    it('should resolve 6', function(done) {
        resolver.resolve6('www.something.com', function(err, response) {
            chai.expect(err).to.be.equal(null);
            chai.assert.isArray(response);
            chai.expect(response).to.have.length.of.at.least(1);
            response.forEach(function(ip) {
                chai.expect(net.isIP(ip)).to.be.ok;
                chai.expect(net.isIPv6(ip)).to.be.ok;
            });

            var expected = (
                dnsentries[cares.NS_C_IN][cares.NS_T_AAAA]['www.something.com']
                .answer
            )
            .filter(function(answer) {
                return answer.type === cares.NS_T_AAAA;
            })
            .map(function(answer) {
                return answer.address;
            });

            chai.expect(response).to.have.lengthOf(expected.length);

            response.forEach(function(answer, index) {
                chai.expect(answer).to.deep.equal(expected[index]);
            });

            done();
        });
    });

    it('should resolve CNAME', function(done) {
        resolver.resolveCname('www.something.com', function(err,
            response) {
            chai.expect(err).to.be.equal(null);
            chai.assert.isArray(response);
            chai.expect(response).to.have.length.of.at.least(1);
            response.forEach(function(data) {
                chai.expect(data).to.be.ok;
            });

            var expected = (
                dnsentries[cares.NS_C_IN][cares.NS_T_CNAME]['www.something.com']
                .answer
            )
            .filter(function(answer) {
                return answer.type === cares.NS_T_CNAME;
            })
            .map(function(answer) {
                return answer.data;
            });

            chai.expect(response).to.have.lengthOf(expected.length);

            response.forEach(function(answer, index) {
                chai.expect(answer).to.deep.equal(expected[index]);
            });

            done();
        });
    });

    it('should query', function(done) {
        resolver.query('www.something.com', function(err, response) {
            chai.expect(err).to.be.equal(null);
            chai.expect(response).to.be.ok;

            chai.expect(response.header).to.be.ok;
            chai.expect(response.header).to.be.an.instanceof(Object);

            chai.expect(response.question).to.be.ok;
            chai.expect(response.question).to.be.an.instanceof(Array);
            chai.expect(response.question).to.have.lengthOf(1);

            var question = response.question[0];
            chai.expect(question.class).to.deep.equal(1);
            chai.expect(question.type).to.deep.equal(1);

            chai.expect(response.authority).to.be.ok;
            chai.expect(response.authority).to.be.an.instanceof(Array);
            chai.expect(response.authority).to.have.lengthOf(0);

            chai.expect(response.additional).to.be.ok;
            chai.expect(response.additional).to.be.an.instanceof(Array);
            chai.expect(response.additional).to.have.lengthOf(0);

            chai.expect(response.answer).to.be.ok;
            chai.expect(response.answer).to.be.an.instanceof(Array);
            chai.expect(response.answer).to.have.length.of.at.least(1);

            done();
        });
    });
});
