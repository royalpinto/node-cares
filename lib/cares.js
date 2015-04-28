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

var cares = require('./../build/Release/cares_wrap'),

    net = require('net'),
    isIp = net.isIP,

    util = require('util'),
    isFunction = util.isFunction || function (arg) {
        return typeof arg === 'function';
    },
    isString = util.isString || function (arg) {
      return typeof arg === 'string';
    },
    isObject = util.isObject || function isObject(arg) {
      return typeof arg === 'object' && arg !== null;
    };


function errnoException(status, errorno, message, syscall) {
  // TODO make this more compatible with ErrnoException from src/node.cc
  // Once all of Node is using this function the ErrnoException from
  // src/node.cc should be removed.

  // For backwards compatibility. libuv returns ENOENT on NXDOMAIN.
  if (errorno == 'ENOENT') {
    errorno = 'ENOTFOUND';
  }

  var e = new Error(message);

  e.errno = e.code = errorno;
  e.status = status;
  e.syscall = syscall;
  return e;
}


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
function makeAsync(callback) {
  if (!isFunction(callback)) {
    return callback;
  }
  return function asyncCallback() {
    if (asyncCallback.immediately) {
      // The API already returned, we can invoke the callback immediately.
      callback.apply(null, arguments);
    } else {
      var args = arguments;
      process.nextTick(function() {
        callback.apply(null, args);
      });
    }
  };
}


function resolver(bindingName, resolver_instance, name, options_, callback_) {

  var options, callback;
  if (!isString(name)) {
    throw new Error('Name must be a string');
  }

  if (isObject(options_)) {
    options = options_;
    if (!isFunction(callback_)) {
      throw new Error('Callback must be a function');
    } else {
      callback = callback_;
    }
  } else if (isFunction(options_)) {
    callback = options_;
  } else {
    throw new Error('Second argument must be a function or an object');
  }

  function onanswer(err, result) {
    if (!err) {
      var params = [null];
      for(var i=1; i< arguments.length; i++) {
          params.push(arguments[i]);
      }
      callback.apply(this, params);
    } else {
      callback(errnoException(err.status, err.errorno, err.message, bindingName));
    }
  }

  callback = makeAsync(callback);
  var err = resolver_instance[bindingName](name, options, onanswer);
  if (err) {
    throw errnoException(err, err, err, bindingName);
  }

  callback.immediately = true;
  return err;
};

var resolveMap = {};

var Resolver = function () {
  this._resolver = new cares.Resolver();
};

Resolver.prototype.query = function(hostname, options_, callback_) {
  var callback,
    options = {};

  if (isFunction(options_)) {
    callback = options_;
  } else {
    options = options_;
    callback = callback_;
  }

  resolver('queryGeneric', this._resolver, hostname, options, callback);
};

Resolver.prototype.resolve4 = resolveMap.A = function(hostname, callback) {
  resolver('queryA', this._resolver, hostname, {}, callback);
};

Resolver.prototype.resolve6 = resolveMap.AAAA = function(hostname, callback) {
  resolver('queryAaaa', this._resolver, hostname, {}, callback);
};

Resolver.prototype.resolveCname = resolveMap.CNAME = function(hostname, callback) {
  resolver('queryCname', this._resolver, hostname, {}, callback);
};

Resolver.prototype.resolveMx = resolveMap.MX = function(hostname, callback) {
  resolver('queryMx', this._resolver, hostname, {}, callback);
};

Resolver.prototype.resolveNs = resolveMap.NS = function(hostname, callback) {
  resolver('queryNs', this._resolver, hostname, {}, callback);
};

Resolver.prototype.resolveTxt = resolveMap.TXT = function(hostname, callback) {
  resolver('queryTxt', this._resolver, hostname, {}, callback);
};

Resolver.prototype.resolveSrv = resolveMap.SRV = function(hostname, callback) {
  resolver('querySrv', this._resolver, hostname, {}, callback);
};

Resolver.prototype.resolveNaptr = resolveMap.NAPTR = function(hostname, callback) {
  resolver('queryNaptr', this._resolver, hostname, {}, callback);
};

Resolver.prototype.resolveSoa = resolveMap.SOA = function(hostname, callback) {
  resolver('querySoa', this._resolver, hostname, {}, callback);
};

Resolver.prototype.reverse = resolveMap.PTR = function(hostname, callback) {
  resolver('getHostByAddr', this._resolver, hostname, {}, callback);
};

Resolver.prototype.lookup = function(name, family_, callback_) {
  var callback,
    family = 0;

  if (isFunction(family_)) {
    callback = family_;
  } else {
    family = family_;
    callback = callback_;
  }

  if (family !== 0 && family !== 4 && family !== 6)
    throw new TypeError('invalid argument: family must be 4 or 6');
  else if (family > 0)
    family = family === 4 ? cares.AF_INET : cares.AF_INET6;

  resolver('getHostByName', this._resolver, name, {
    family: family
  }, function (err, result, family) {
      if (err) {
          callback(err);
      } else {
          family = family === cares.AF_INET ? 4 : 6;
          callback(err, result.pop() || null, family);
      }
  });
};

Resolver.prototype.resolve = function(hostname, type_, callback_) {
  var resolver, callback;
  if (isString(type_)) {
    resolver = resolveMap[type_];
    callback = callback_;
  } else if (isFunction(type_)) {
    resolver = exports.resolve4;
    callback = type_;
  } else {
    throw new Error('Type must be a string');
  }

  if (isFunction(resolver)) {
    return resolver.call(this, hostname, callback);
  } else {
    throw new Error('Unknown type "' + type_ + '"');
  }
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

    if (ver)
      return newSet.push([ver, serv]);

    var match = serv.match(/\[(.*)\](:\d+)?/);

    // we have an IPv6 in brackets
    if (match) {
      ver = isIp(match[1]);
      if (ver)
        return newSet.push([ver, match[1]]);
    }

    var s = serv.split(/:\d+$/)[0];
    ver = isIp(s);

    if (ver)
      return newSet.push([ver, s]);

    throw new Error('IP address is not properly formatted: ' + serv);
  });

  var err = this._resolver.setServers(newSet);

  if (err) {
    // reset the servers to the old servers, because ares probably unset them
    this._resolver.setServers(orig.join(','));

    throw new Error('c-ares failed to set servers: "' + err.message +
                    '" [' + servers + ']');
  }
};


exports.Resolver = Resolver;

var defaultResolver = new Resolver();

exports.query = function(hostname, options, callback) {
  return defaultResolver.query(hostname, options, callback);
};

exports.resolve4 = function(hostname, callback) {
  return defaultResolver.resolve4(hostname, callback);
};

exports.resolve6 = function(hostname, callback) {
  return defaultResolver.resolve6(hostname, callback);
};

exports.resolveCname = function(hostname, callback) {
  return defaultResolver.resolveCname(hostname, callback);
};

exports.resolveMx = function(hostname, callback) {
  return defaultResolver.resolveMx(hostname, callback);
};

exports.resolveNs = function(hostname, callback) {
  return defaultResolver.resolveNs(hostname, callback);
};

exports.resolveTxt = function(hostname, callback) {
  return defaultResolver.resolveTxt(hostname, callback);
};

exports.resolveSrv = function(hostname, callback) {
  return defaultResolver.resolveSrv(hostname, callback);
};

exports.resolveNaptr = function(hostname, callback) {
  return defaultResolver.resolveNaptr(hostname, callback);
};

exports.resolveSoa = function(hostname, callback) {
  return defaultResolver.resolveSoa(hostname, callback);
};

exports.reverse = function(hostname, callback) {
  return defaultResolver.reverse(hostname, callback);
};

exports.lookup = function(name, family, callback) {
  return defaultResolver.lookup(name, family, callback);
};

exports.resolve = function(hostname, type, callback) {
  return defaultResolver.resolve(hostname, type, callback);
};

exports.getServers = function() {
  return defaultResolver.getServers();
};

exports.setServers = function(servers) {
  return defaultResolver.setServers(servers);
};


// uv_getaddrinfo flags
exports.ADDRCONFIG = cares.AI_ADDRCONFIG;
exports.V4MAPPED = cares.AI_V4MAPPED;

// ERROR CODES
exports.NODATA = 'ENODATA';
exports.FORMERR = 'EFORMERR';
exports.SERVFAIL = 'ESERVFAIL';
exports.NOTFOUND = 'ENOTFOUND';
exports.NOTIMP = 'ENOTIMP';
exports.REFUSED = 'EREFUSED';
exports.BADQUERY = 'EBADQUERY';
exports.ADNAME = 'EADNAME';
exports.BADFAMILY = 'EBADFAMILY';
exports.BADRESP = 'EBADRESP';
exports.CONNREFUSED = 'ECONNREFUSED';
exports.TIMEOUT = 'ETIMEOUT';
exports.EOF = 'EOF';
exports.FILE = 'EFILE';
exports.NOMEM = 'ENOMEM';
exports.DESTRUCTION = 'EDESTRUCTION';
exports.BADSTR = 'EBADSTR';
exports.BADFLAGS = 'EBADFLAGS';
exports.NONAME = 'ENONAME';
exports.BADHINTS = 'EBADHINTS';
exports.NOTINITIALIZED = 'ENOTINITIALIZED';
exports.LOADIPHLPAPI = 'ELOADIPHLPAPI';
exports.ADDRGETNETWORKPARAMS = 'EADDRGETNETWORKPARAMS';
exports.CANCELLED = 'ECANCELLED';

/* type constants */
exports.NS_T_INVALID = 0;	/* Cookie. */
exports.NS_T_A = 1;		/* Host address. */
exports.NS_T_NS = 2;		/* Authoritative server. */
exports.NS_T_MD = 3;		/* Mail destination. */
exports.NS_T_MF = 4;		/* Mail forwarder. */
exports.NS_T_CNAME = 5;		/* Canonical name. */
exports.NS_T_SOA = 6;		/* Start of authority zone. */
exports.NS_T_MB = 7;		/* Mailbox domain name. */
exports.NS_T_MG = 8;		/* Mail group member. */
exports.NS_T_MR = 9;		/* Mail rename name. */
exports.NS_T_NULL = 10;		/* Null resource record. */
exports.NS_T_WKS = 11;		/* Well known service. */
exports.NS_T_PTR = 12;		/* Domain name pointer. */
exports.NS_T_HINFO = 13;	/* Host information. */
exports.NS_T_MINFO = 14;	/* Mailbox information. */
exports.NS_T_MX = 15;		/* Mail routing information. */
exports.NS_T_TXT = 16;		/* Text strings. */
exports.NS_T_RP = 17;		/* Responsible person. */
exports.NS_T_AFSDB = 18;	/* AFS cell database. */
exports.NS_T_X25 = 19;		/* X_25 calling address. */
exports.NS_T_ISDN = 20;		/* ISDN calling address. */
exports.NS_T_RT = 21;		/* Router. */
exports.NS_T_NSAP = 22;		/* NSAP address. */
exports.NS_T_NSAP_PTR = 23;	/* Reverse NSAP lookup (deprecated). */
exports.NS_T_SIG = 24;		/* Security signature. */
exports.NS_T_KEY = 25;		/* Security key. */
exports.NS_T_PX = 26;		/* X.400 mail mapping. */
exports.NS_T_GPOS = 27;		/* Geographical position (withdrawn). */
exports.NS_T_AAAA = 28;		/* Ip6 Address. */
exports.NS_T_LOC = 29;		/* Location Information. */
exports.NS_T_NXT = 30;		/* Next domain (security). */
exports.NS_T_EID = 31;		/* Endpoint identifier. */
exports.NS_T_NIMLOC = 32;	/* Nimrod Locator. */
exports.NS_T_SRV = 33;		/* Server Selection. */
exports.NS_T_ATMA = 34;		/* ATM Address */
exports.NS_T_NAPTR = 35;	/* Naming Authority PoinTeR */
exports.NS_T_KX = 36;		/* Key Exchange */
exports.NS_T_CERT = 37;		/* Certification record */
exports.NS_T_A6 = 38;		/* IPv6 address (deprecates AAAA) */
exports.NS_T_DNAME = 39;	/* Non-terminal DNAME (for IPv6) */
exports.NS_T_SINK = 40;		/* Kitchen sink (experimentatl) */
exports.NS_T_OPT = 41;		/* EDNS0 option (meta-RR) */
exports.NS_T_TKEY = 249;	/* Transaction key */
exports.NS_T_TSIG = 250;	/* Transaction signature. */
exports.NS_T_IXFR = 251;	/* Incremental zone transfer. */
exports.NS_T_AXFR = 252;	/* Transfer zone of authority. */
exports.NS_T_MAILB = 253;	/* Transfer mailbox records. */
exports.NS_T_MAILA = 254;	/* Transfer mail agent records. */
exports.NS_T_ANY = 255;		/* Wildcard match. */
exports.NS_T_ZXFR = 256;	/* BIND-specific, nonstandard. */
exports.NS_T_MAX = 65536;

/* class constants */
exports.NS_C_INVALID = 0;	/* Cookie. */
exports.NS_C_IN = 1;		/* Internet. */
exports.NS_C_2 = 2;		/* unallocated/unsupported. */
exports.NS_C_CHAOS = 3;		/* MIT Chaos-net. */
exports.NS_C_HS = 4;		/* MIT Hesiod. */
/* Query class values which do not appear in resource records */
exports.NS_C_NONE = 254;	/* for prereq. sections in update requests */
exports.NS_C_ANY = 255;		/* Wildcard match. */
exports.NS_C_MAX = 6553;
