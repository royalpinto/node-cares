/*
The follwoing code adapted from node's dns module and license is as follows
*/

// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// 'Software'), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var cares = require('./../build/Release/cares_wrap');
var Q = require('q');
var net = require('net');
var isIp = net.isIP;
var util = require('util');

var isFunction = util.isFunction || function(arg) {
    return typeof arg === 'function';
};

var isString = util.isString || function(arg) {
    return typeof arg === 'string';
};

var isObject = util.isObject || function isObject(arg) {
    return typeof arg === 'object' && arg !== null;
};


var errnoException = function(status, errorno, message, syscall) {
    // TODO make this more compatible with ErrnoException from src/node.cc
    // Once all of Node is using this function the ErrnoException from
    // src/node.cc should be removed.

    // For backwards compatibility. libuv returns ENOENT on NXDOMAIN.
    if (errorno === 'ENOENT') {
        errorno = 'ENOTFOUND';
    }

    var e = new Error(message);

    e.errno = e.code = errorno;
    e.status = status;
    e.syscall = syscall;
    return e;
};


// c-ares invokes a callback either synchronously or asynchronously,
// but the dns API should always invoke a callback asynchronously.
//
// This function makes sure that the callback is invoked asynchronously.
// It returns a function that invokes the callback within nextTick().
//
// To avoid invoking unnecessary nextTick(), `immediately` property of
// returned function should be set to true after c-ares returned.
//
// Usage:
//
// function someAPI(callback) {
//   callback = makeAsync(callback);
//   channel.someAPI(..., callback);
//   callback.immediately = true;
// }
var makeAsync = function(callback) {
    var instance = this;
    if (!isFunction(callback)) {
        return callback;
    }
    return function asyncCallback() {
        if (asyncCallback.immediately) {
            // The API already returned, we can invoke the callback immediately.
            callback.apply(instance, arguments);
        } else {
            var args = arguments;
            process.nextTick(function() {
                callback.apply(instance, args);
            });
        }
    };
};

// A dummy function to be used as a callback, if actual callback isn't passed.
var dummy = function() {};

var resolver = function(bindingName, resolver, name, options_, callback_) {
    var deferred = Q.defer();
    var options;
    var callback;

    if (!isString(name)) {
        throw new Error('Name must be a string');
    }

    if (isObject(options_)) {
        options = options_;
        // If callback is passed, it should be function.
        if (callback_ && !isFunction(callback_)) {
            throw new Error('Callback must be a function');
        } else {
            // Use dummy function if actual callback isn't passed.
            callback = callback_ || dummy;
        }
    } else if (isFunction(options_)) {
        callback = options_;
    } else if (options_) {
        throw new Error('Second argument must be a function or an object');
    } else {
        // If callback and options are not passed.
        callback = dummy;
    }

    var onanswer = function(err) {
        if (err) {
            var error = errnoException(err.status, err.errorno,
                err.message, bindingName);
            callback.call(resolver, error);
            deferred.reject(error);
        } else {
            var params = [null];
            for (var i = 1; i < arguments.length; i++) {
                params.push(arguments[i]);
            }
            callback.apply(resolver, params);
            deferred.resolve.apply(this, params.slice(1));
        }
    };

    callback = makeAsync.call(resolver, callback);
    var err = resolver._resolver[bindingName](name, options, onanswer);
    if (err) {
        throw errnoException(err, err, err, bindingName);
    }

    callback.immediately = true;
    return deferred.promise;
};

var resolveMap = {};


/**
 * Initialize the resolver with given options.
 * @param {Object} [options={}] The options to be used with the resolver.
 * @param {Number} [options.timeout=5000] The number of milliseconds each
 * name server should be given to respond to a query on the first try.
 * (After the first try, the timeout algorithm becomes more complicated,
 * but scales linearly with the value of timeout.)
 * @param {Number} [options.tries=4] The number of times the resolver should try
 * contacting each name server before giving up.
 * @param {Number} [options.ndots=1] The number of dots which must be present in
 * a domain name for it to be queried for "as is" prior to querying for it with
 * the default domain extensions appended. The default value is 1 unless set
 * otherwise by resolv.conf or the RES_OPTIONS environment variable.
 * @param {Number} [options.tcp_port] The tcp port to use for queries.
 * @param {Number} [options.udp_port] The udp port to use for queries.
 * @param {Array} [options.servers] An array of IP addresses as strings,
 * set them as the servers to use for resolving.
 * @param {Number} [options.flags] The flags field should be the bitwise or
 * of some subset of ARES_FLAG_*.
 * @class
 * @classdesc Instances of the Resolver class represent a single `ares_channel`.
 */
var Resolver = function Resolver(options) {
    if (!(this instanceof Resolver)) {
        return new Resolver(options);
    }

    options = options || {};

    if (!isObject(options)) {
        throw new Error('options must be an object');
    }

    this._resolver = new cares.Resolver(options);

    if (options.servers) {
        this.setServers(options.servers);
    }
};

Resolver.prototype.query = function(hostname, options_, callback_) {
    var callback;
    var options = {};

    if (isFunction(options_)) {
        callback = options_;
    } else {
        options = options_;
        callback = callback_;
    }

    return (resolver('queryGeneric', this,
        hostname, options, callback));
};

Resolver.prototype.resolve4 = resolveMap.A = function(hostname, callback) {
    return resolver('queryA', this, hostname, {}, callback);
};

Resolver.prototype.resolve6 = resolveMap.AAAA = function(hostname, callback) {
    return resolver('queryAaaa', this, hostname, {}, callback);
};

Resolver.prototype.resolveCname = resolveMap.CNAME = function(hostname,
    callback) {
    return resolver('queryCname', this, hostname, {}, callback);
};

Resolver.prototype.resolveMx = resolveMap.MX = function(hostname, callback) {
    return resolver('queryMx', this, hostname, {}, callback);
};

Resolver.prototype.resolveNs = resolveMap.NS = function(hostname, callback) {
    return resolver('queryNs', this, hostname, {}, callback);
};

Resolver.prototype.resolveTxt = resolveMap.TXT = function(hostname, callback) {
    return resolver('queryTxt', this, hostname, {}, callback);
};

Resolver.prototype.resolveSrv = resolveMap.SRV = function(hostname, callback) {
    return resolver('querySrv', this, hostname, {}, callback);
};

Resolver.prototype.resolveNaptr = resolveMap.NAPTR = function(hostname,
    callback) {
    return resolver('queryNaptr', this, hostname, {}, callback);
};

Resolver.prototype.resolveSoa = resolveMap.SOA = function(hostname,
    callback) {
    return resolver('querySoa', this, hostname, {}, callback);
};

Resolver.prototype.reverse = resolveMap.PTR = function(hostname, callback) {
    return resolver('getHostByAddr', this, hostname, {}, callback);
};

Resolver.prototype.lookup = function(name, family_, callback_) {
    var callback;
    var family = 0;

    if (isFunction(family_)) {
        callback = family_;
    } else {
        family = family_;
        callback = callback_;
    }

    if (family !== 0 && family !== 4 && family !== 6) {
        throw new TypeError('invalid argument: family must be 4 or 6');
    } else if (family > 0) {
        family = family === 4 ? cares.AF_INET : cares.AF_INET6;
    }

    return resolver('getHostByName', this, name, {
        family: family,
    }, function(err, result, family) {
        if (err) {
            callback(err);
        } else {
            family = family === cares.AF_INET ? 4 : 6;
            callback(err, result.pop() || null, family);
        }
    });
};

Resolver.prototype.resolve = function(hostname, type_, callback_) {
    var resolver;
    var callback;
    if (isString(type_)) {
        resolver = resolveMap[type_];
        callback = callback_;
    } else if (isFunction(type_)) {
        resolver = this.resolve4;
        callback = type_;
    } else {
        throw new Error('Type must be a string');
    }

    if (!isFunction(resolver)) {
        throw new Error('Unknown type "' + type_ + '"');
    }

    return resolver.call(this, hostname, callback);
};

Resolver.prototype.getServers = function() {
    return this._resolver.getServers();
};

Resolver.prototype.setServers = function(servers) {
    // cache the original servers because in the event of an error setting the
    // servers cares won't have any servers available for resolution
    var orig = this._resolver.getServers();

    var newSet = [];

    servers.forEach(function(serv) {
        var ver = isIp(serv);

        if (ver) {
            return newSet.push([ver, serv]);
        }

        var match = serv.match(/\[(.*)\](:\d+)?/);

        // we have an IPv6 in brackets
        if (match) {
            ver = isIp(match[1]);
            if (ver) {
                return newSet.push([ver, match[1]]);
            }
        }

        var s = serv.split(/:\d+$/)[0];
        ver = isIp(s);

        if (ver) {
            return newSet.push([ver, s]);
        }

        throw new Error('IP address is not properly formatted: ' + serv);
    });

    var err = this._resolver.setServers(newSet);

    if (err) {
        // reset the servers to the old servers,
        // because ares probably unset them
        this._resolver.setServers(orig.join(','));

        throw new Error('c-ares failed to set servers: "' + err.message +
                        '" [' + servers + ']');
    }
};

var defaultResolver = new Resolver();

module.exports = defaultResolver;

module.exports.Resolver = Resolver;

// uv_getaddrinfo flags
module.exports.ADDRCONFIG = cares.AI_ADDRCONFIG;
module.exports.V4MAPPED = cares.AI_V4MAPPED;

// ERROR CODES
module.exports.NODATA = 'ENODATA';
module.exports.FORMERR = 'EFORMERR';
module.exports.SERVFAIL = 'ESERVFAIL';
module.exports.NOTFOUND = 'ENOTFOUND';
module.exports.NOTIMP = 'ENOTIMP';
module.exports.REFUSED = 'EREFUSED';
module.exports.BADQUERY = 'EBADQUERY';
module.exports.ADNAME = 'EADNAME';
module.exports.BADFAMILY = 'EBADFAMILY';
module.exports.BADRESP = 'EBADRESP';
module.exports.CONNREFUSED = 'ECONNREFUSED';
module.exports.TIMEOUT = 'ETIMEOUT';
module.exports.EOF = 'EOF';
module.exports.FILE = 'EFILE';
module.exports.NOMEM = 'ENOMEM';
module.exports.DESTRUCTION = 'EDESTRUCTION';
module.exports.BADSTR = 'EBADSTR';
module.exports.BADFLAGS = 'EBADFLAGS';
module.exports.NONAME = 'ENONAME';
module.exports.BADHINTS = 'EBADHINTS';
module.exports.NOTINITIALIZED = 'ENOTINITIALIZED';
module.exports.LOADIPHLPAPI = 'ELOADIPHLPAPI';
module.exports.ADDRGETNETWORKPARAMS = 'EADDRGETNETWORKPARAMS';
module.exports.CANCELLED = 'ECANCELLED';

/* type constants */
module.exports.NS_T_INVALID = 0;	/* Cookie. */
module.exports.NS_T_A = 1;		/* Host address. */
module.exports.NS_T_NS = 2;		/* Authoritative server. */
module.exports.NS_T_MD = 3;		/* Mail destination. */
module.exports.NS_T_MF = 4;		/* Mail forwarder. */
module.exports.NS_T_CNAME = 5;		/* Canonical name. */
module.exports.NS_T_SOA = 6;		/* Start of authority zone. */
module.exports.NS_T_MB = 7;		/* Mailbox domain name. */
module.exports.NS_T_MG = 8;		/* Mail group member. */
module.exports.NS_T_MR = 9;		/* Mail rename name. */
module.exports.NS_T_NULL = 10;		/* Null resource record. */
module.exports.NS_T_WKS = 11;		/* Well known service. */
module.exports.NS_T_PTR = 12;		/* Domain name pointer. */
module.exports.NS_T_HINFO = 13;	/* Host information. */
module.exports.NS_T_MINFO = 14;	/* Mailbox information. */
module.exports.NS_T_MX = 15;		/* Mail routing information. */
module.exports.NS_T_TXT = 16;		/* Text strings. */
module.exports.NS_T_RP = 17;		/* Responsible person. */
module.exports.NS_T_AFSDB = 18;	/* AFS cell database. */
module.exports.NS_T_X25 = 19;		/* X_25 calling address. */
module.exports.NS_T_ISDN = 20;		/* ISDN calling address. */
module.exports.NS_T_RT = 21;		/* Router. */
module.exports.NS_T_NSAP = 22;		/* NSAP address. */
module.exports.NS_T_NSAP_PTR = 23;	/* Reverse NSAP lookup (deprecated). */
module.exports.NS_T_SIG = 24;		/* Security signature. */
module.exports.NS_T_KEY = 25;		/* Security key. */
module.exports.NS_T_PX = 26;		/* X.400 mail mapping. */
module.exports.NS_T_GPOS = 27;		/* Geographical position (withdrawn). */
module.exports.NS_T_AAAA = 28;		/* Ip6 Address. */
module.exports.NS_T_LOC = 29;		/* Location Information. */
module.exports.NS_T_NXT = 30;		/* Next domain (security). */
module.exports.NS_T_EID = 31;		/* Endpoint identifier. */
module.exports.NS_T_NIMLOC = 32;	/* Nimrod Locator. */
module.exports.NS_T_SRV = 33;		/* Server Selection. */
module.exports.NS_T_ATMA = 34;		/* ATM Address */
module.exports.NS_T_NAPTR = 35;	/* Naming Authority PoinTeR */
module.exports.NS_T_KX = 36;		/* Key Exchange */
module.exports.NS_T_CERT = 37;		/* Certification record */
module.exports.NS_T_A6 = 38;		/* IPv6 address (deprecates AAAA) */
module.exports.NS_T_DNAME = 39;	/* Non-terminal DNAME (for IPv6) */
module.exports.NS_T_SINK = 40;		/* Kitchen sink (experimentatl) */
module.exports.NS_T_OPT = 41;		/* EDNS0 option (meta-RR) */
module.exports.NS_T_TKEY = 249;	/* Transaction key */
module.exports.NS_T_TSIG = 250;	/* Transaction signature. */
module.exports.NS_T_IXFR = 251;	/* Incremental zone transfer. */
module.exports.NS_T_AXFR = 252;	/* Transfer zone of authority. */
module.exports.NS_T_MAILB = 253;	/* Transfer mailbox records. */
module.exports.NS_T_MAILA = 254;	/* Transfer mail agent records. */
module.exports.NS_T_ANY = 255;		/* Wildcard match. */
module.exports.NS_T_ZXFR = 256;	/* BIND-specific, nonstandard. */
module.exports.NS_T_MAX = 65536;

/* class constants */
module.exports.NS_C_INVALID = 0;	/* Cookie. */
module.exports.NS_C_IN = 1;		/* Internet. */
module.exports.NS_C_2 = 2;		/* unallocated/unsupported. */
module.exports.NS_C_CHAOS = 3;		/* MIT Chaos-net. */
module.exports.NS_C_HS = 4;		/* MIT Hesiod. */
/* Query class values which do not appear in resource records */
module.exports.NS_C_NONE = 254;	/* for prereq. sections in update requests */
module.exports.NS_C_ANY = 255;		/* Wildcard match. */
module.exports.NS_C_MAX = 6553;

module.exports.ARES_FLAG_USEVC = cares.ARES_FLAG_USEVC;
module.exports.ARES_FLAG_PRIMARY = cares.ARES_FLAG_PRIMARY;
module.exports.ARES_FLAG_IGNTC = cares.ARES_FLAG_IGNTC;
module.exports.ARES_FLAG_NORECURSE = cares.ARES_FLAG_NORECURSE;
module.exports.ARES_FLAG_STAYOPEN = cares.ARES_FLAG_STAYOPEN;
module.exports.ARES_FLAG_NOSEARCH = cares.ARES_FLAG_NOSEARCH;
module.exports.ARES_FLAG_NOALIASES = cares.ARES_FLAG_NOALIASES;
