var http          = require('http');
var https           = require('https');
var utilities = require('wircho-utilities');
var pad = utilities.pad;
var def = utilities.def;
var fallback = utilities.fallback;
var nullFallback = utilities.nullFallback;
var err = utilities.err;
var errstr = utilities.errstr;
var errdict = utilities.errdict;
var geterr = utilities.geterr;
var routeerr = utilities.routeerr;
var projf = utilities.projf;
var projff = utilities.projff;
var mutate = utilities.mutate;
var remove = utilities.remove;
var rotate = utilities.rotate;
var loop = utilities.loop;
var Maybe = utilities.Maybe;

// import {
// //Utilities
//   pad,
//   def,
//   fallback,
//   nullFallback,
//   err,
//   errstr,
//   errdict,
//   geterr,
//   projf,
//   projff,
// //Object utilities
//   mutate,
//   remove,
//   rotate,
//   loop
// } from 'wircho-utilities';

// SHA1
function b64_hmac_sha1(k,d,_p,_z){
  // heavily optimized and compressed version of http://pajhome.org.uk/crypt/md5/sha1.js
  // _p = b64pad, _z = character size; not used here but I left them available just in case
  if(!_p){_p='=';}if(!_z){_z=8;}function _f(t,b,c,d){if(t<20){return(b&c)|((~b)&d);}if(t<40){return b^c^d;}if(t<60){return(b&c)|(b&d)|(c&d);}return b^c^d;}function _k(t){return(t<20)?1518500249:(t<40)?1859775393:(t<60)?-1894007588:-899497514;}function _s(x,y){var l=(x&0xFFFF)+(y&0xFFFF),m=(x>>16)+(y>>16)+(l>>16);return(m<<16)|(l&0xFFFF);}function _r(n,c){return(n<<c)|(n>>>(32-c));}function _c(x,l){x[l>>5]|=0x80<<(24-l%32);x[((l+64>>9)<<4)+15]=l;var w=[80],a=1732584193,b=-271733879,c=-1732584194,d=271733878,e=-1009589776;for(var i=0;i<x.length;i+=16){var o=a,p=b,q=c,r=d,s=e;for(var j=0;j<80;j++){if(j<16){w[j]=x[i+j];}else{w[j]=_r(w[j-3]^w[j-8]^w[j-14]^w[j-16],1);}var t=_s(_s(_r(a,5),_f(j,b,c,d)),_s(_s(e,w[j]),_k(j)));e=d;d=c;c=_r(b,30);b=a;a=t;}a=_s(a,o);b=_s(b,p);c=_s(c,q);d=_s(d,r);e=_s(e,s);}return[a,b,c,d,e];}function _b(s){var b=[],m=(1<<_z)-1;for(var i=0;i<s.length*_z;i+=_z){b[i>>5]|=(s.charCodeAt(i/8)&m)<<(32-_z-i%32);}return b;}function _h(k,d){var b=_b(k);if(b.length>16){b=_c(b,k.length*_z);}var p=[16],o=[16];for(var i=0;i<16;i++){p[i]=b[i]^0x36363636;o[i]=b[i]^0x5C5C5C5C;}var h=_c(p.concat(_b(d)),512+d.length*_z);return _c(o.concat(h),512+160);}function _n(b){var t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",s='';for(var i=0;i<b.length*4;i+=3){var r=(((b[i>>2]>>8*(3-i%4))&0xFF)<<16)|(((b[i+1>>2]>>8*(3-(i+1)%4))&0xFF)<<8)|((b[i+2>>2]>>8*(3-(i+2)%4))&0xFF);for(var j=0;j<4;j++){if(i*8+j*6>b.length*32){s+=_p;}else{s+=t.charAt((r>>6*(3-j))&0x3F);}}}return s;}function _x(k,d){return _n(_h(k,d));}return _x(k,d);
}

function randomNonce(size) {
  var text = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for( var i = 0; i < size; i += 1) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

function secondsTS() {
  return Math.floor(Date.now() / 1000);
}

// QueryItem type
function QueryItem(key,value) {
  this.key = key;
  this.value = value;
  
  this.getComp = function() {
    return (def(this.key) ? encodeURIComponent(this.key) : "")
      + ((def(this.key) && def(this.value)) ? ("=" + encodeURIComponent(this.value)) : "")
  }
};

QueryItem.arrayFromString = function(string) {
  return string.split("&").map(function(str) {
    var arr = str.split("=");
    return new QueryItem(decodeURIComponent(arr[0]), (arr.length > 1) ? decodeURIComponent(arr[1]) : undefined);
  });
};

QueryItem.stringFromArray = function(array) {
  return array.map(function(q) { return q.getComp() }).join("");
};

QueryItem.dictionaryFromArray = function(array) {
  var dict = {};
  array.map(function(q) {
    dict[q.key] = q.value;
  });
  return dict;
};

QueryItem.dictionaryFromString = function(string) {
  return QueryItem.dictionaryFromArray(QueryItem.arrayFromString(string));
};

// URLComponents type
function URLComponents(url) {
  if (def(url)) {
    var u = url;
    var hashSplit = u.split("#");
    if (hashSplit.length > 1) {
      u = hashSplit.shift();
      this.fragment = hashSplit.join("#");
    }
    var qSplit = u.split("?");
    if (qSplit.lenght > 1) {
      u = qSplit.shift();
      this.params = QueryItem.arrayFromString(qSplit.join("?"));
    } else {
      this.params = new Array();
    }
    var bSplit = u.split("://");
    if (bSplit.length > 1) {
      this.protocol = bSplit.shift();
      u = bSplit.join("://");
    } else {
      this.protocol = "http";
    }
    var pSplit = u.split("/");
    if (pSplit.length > 1) {
      u = pSplit.shift();
      this.path = "/" + pSplit.join("/");
    }
    this.base = u;
  };
  
  this.getURL = function() {
    return this.protocol + "://" + this.base + this.path
      + ((def(this.params) && this.params.length > 0) ? ("?" + QueryItem.stringFromArray(this.params)) : "")
      + (def(this.fragment) ? ("#" + this.fragment) : "")
  };

  this.getProtocolToPath = function() {
    return this.protocol + "://" + this.base + this.path;
  };
  
  this.plusParams = function(params) {
    var comps = new URLComponents();
    comps.protocol = this.protocol;
    comps.base = this.base;
    comps.path = this.path;
    comps.fragment = this.fragment;
    comps.params = new Array();
    for (var i = 0; i < this.params.length; i += 1) {
      comps.params.push(this.params[i]);
    }
    for (var i = 0; i < params.length; i += 1) {
      comps.params.push(params[i]);
    }
    return comps;
  };
}

// Request type
function request(method,url,responseType) {
  return new Request(method,url,responseType);
}

var RequestFrontEndHelpers = {
  createHTTPRequest: function(r) {
    var req = new XMLHttpRequest();
    req.responseType = fallback(r.responseType,"");
    req.onload = function() {
      r.loadMaybe.resolve({request: req});
    };
    if (r.dataCallbacks.length > 0) {
      var responseCaret = 0;
      req.addEventListener('progress', function() {
        var data = req.response.substring(responseCaret);
        responseCaret = req.response.length;
        var info = {request: req, data};
        for (var i=0; i<r.dataCallbacks.length; i+=1) {
          var c = r.dataCallbacks[i];
          c(info);
        }
      }, false);
    }
    req.onerror = function() {
      r.errorMaybe.resolve({request: req});
    };
    return req;
  }.bind(null),
  openHTTPRequest: function(r) {
    console.log("calling openHTTPRequest on:");
    console.log(r);
    r.req.open(r.method, r.getURL());
    loop(r.headers,function(key,value) {
      r.req.setRequestHeader(key,value);
    });
  }.bind(null),
  sendHTTPRequest: function(r) {
    if (r.method === "GET" || r.method === "HEAD") {
      r.req.send();
    } else {
      if (def(r.body)) {
        r.req.send(r.body);
      } else if (r.params.length > 0) {
        r.req.send(QueryItem.stringFromArray(r.params));
      } else {
        r.req.send();
      }
    }
  }.bind(null)
}

var RequestBackEndHelpers = {
  createHTTPRequest: function(r) {
    var proto = (r.urlComponents.protocol === "https") ? https : http;
    var path = r.urlComponents.path;
    if (r.method === "GET" || r.method === "HEAD") {
      var queryString = QueryItem.stringFromArray(r.getAllParams());
      path = path + "?" + queryString;
    }
    var req = proto.request({
      method: r.method,
      host: r.urlComponents.base,
      path: path,
      headers: r.headers
    }, function(response) {
      var body = "";
      response.on("data", function(d) {
        if (r.needsLoadedData) {
          body += d;
        }
        var info = {data: d, response};
        for (var i=0; i<r.dataCallbacks.length; i+=1) {
          var c = r.dataCallbacks[i];
          c(info);
        }
      });
      if (r.needsLoadedData) {
        response.on("end", function(d) {
          if (r.responseType === "json") {
            var json = undefined;
            try {
              json = JSON.parse(body);
            } catch (e) {
              r.loadMaybe.resolve({content:body,response});
              return;
            }
            r.loadMaybe.resolve({content:json,response});
          } else {
            r.loadMaybe.resolve({content:body,response});
          }
        });
      }
    });
    req.on("error", function(error) {
      r.errorMaybe.resolve(error);
    });
    return req;
  }.bind(null),
  openHTTPRequest: function(r) {
    // Nothing here
  }.bind(null),
  sendHTTPRequest: function(r) {
    if (def(r.body)) {
      r.req.write(r.body);
    } else if (r.method !== "GET" && r.method !== "POST") {
      r.req.write(QueryItem.stringFromArray(r.getAllParams()));
    }
    r.req.end();
  }.bind(null)
  
}

var RequestHelpers = {
  using: RequestFrontEndHelpers,
  use: function(helpers) {
    this.using = helpers;
  }
};

function Request(method,url,responseType) {
  this.method = method;
  this.urlComponents = new URLComponents(url);
  this.params = new Array();
  this.headers = {};
  this.body = undefined;
  
  this.req = undefined;
  this.responseType = responseType;
  this.opened = false;
  this.sent = false;
  this.loadMaybe = new Maybe();
  this.errorMaybe = new Maybe();
  this.dataCallbacks = new Array();

  this.needsLoadedData = false;
  
  this.getAllParams = function() {
    return this.urlComponents.plusParams(this.params).params;
  }

  this.getURL = function() {
    if (this.method === "GET" || this.method === "HEAD") {
      var c = this.urlComponents.plusParams(this.params);
      return c.getURL();
    } else {
      return this.urlComponents.getURL();
    }
  }.bind(this);
  
  createReq = function() {
    if (!def(this.req)) {
      this.req = RequestHelpers.using.createHTTPRequest(this);
    }
  }.bind(this);
  
  this.setParam = function(key,value) {
    this.params.push(new QueryItem(key,value));
    return this;
  };
  
  this.setParams = function(dict) {
    loop(dict,function(key,value){ this.params.push(new QueryItem(key,value)) }.bind(this));
    return this;
  }
  
  this.setBody = function(body) {
    this.body = body;
    return this;
  };
  
  this.setHeaders = function(dict) {
    loop(dict,function(key,value) {
      this.headers[key] = value;
    }.bind(this));
    return this;
  }
  
  this.setHeader = function(key,value) {
    var obj = {};
    obj[key] = value;
    return this.setHeaders(obj);
  }
  
  this.open = function() {
    if (this.opened) { return this; }
    this.opened = true;
    createReq();
    console.log("calling open on:");
    console.log(this);
    RequestHelpers.using.openHTTPRequest(this);
    return this;
  };
  
  this.onLoad = function(callback) {
    this.needsLoadedData = true;
    this.loadMaybe.promise.then(callback);
    return this;
  };

  this.onData = function(callback) {
    this.dataCallbacks.push(callback);
    return this;
  }
  
  this.onError = function(callback) {
    this.errorMaybe.promise.then(callback);
    return this;
  };
  
  this.send = function() {
    if (this.sent) { return this; }
    this.sent = true;
    this.open();
    RequestHelpers.using.sendHTTPRequest(this);
    return this;
  };
}

// Twitter stuff
const TWITTER_KEY = process.env.TWITTER_KEY;
const TWITTER_SECRET = process.env.TWITTER_SECRET;
const TWITTER_CALLBACK = process.env.TWITTER_CALLBACK;

var Twitter = {
  consumerKey: TWITTER_KEY,
  consumerSecret: TWITTER_SECRET,
  callback: TWITTER_CALLBACK,
  signatureMethod: "HMAC-SHA1",
  oauthVersion: "1.0"
}

Twitter.generateNonce = function() {
  return randomNonce(32);
}.bind(Twitter);

Twitter.generateTimestamp = function() {
  return secondsTS();
}.bind(Twitter);

Twitter.generateHeaderDictionary = function(oauthToken, moreParams) {
  var dict = {
    oauth_version: this.oauthVersion,
    oauth_nonce: this.generateNonce(),
    oauth_timestamp: this.generateTimestamp(),
    oauth_signature_method: this.signatureMethod,
    oauth_consumer_key: this.consumerKey
  }
  if (def(oauthToken)) {
    dict.oauth_token = oauthToken;
  } else {
    dict.oauth_callback = this.callback;
  }
  if (def(moreParams)) {
    loop(moreParams,function(key,value) {
      dict[key] = value;
    });
  }
  return dict;
}.bind(Twitter);

Twitter.generateHeaderDictionaryWithSignature = function(req, oauthToken, tokenSecret, moreParams) {
  var headerDictionary = this.generateHeaderDictionary(oauthToken, moreParams);
  headerDictionary.oauth_signature = this.generateSignature(req, headerDictionary, tokenSecret);
  return headerDictionary;
}.bind(Twitter);

Twitter.generateOAuthHeader = function(headerDictionary) {
  var items = loop(headerDictionary,function(key,value){return new QueryItem(key,value)});
  items.sort(function(p,q){ return (p.key < q.key) ? (-1) : 1 });
  return "OAuth " + loop(items,function(key,item){ return encodeURIComponent(item.key) + "=\"" + encodeURIComponent(item.value) + "\"" }).join(",");
}.bind(Twitter);

Twitter.generateSignature = function(request, headerDictionary, tokenSecret) {
  var method = request.method;
  var url = request.urlComponents.getProtocolToPath();
  var params = new Array();
  loop(request.urlComponents.params,function(i,q){ params.push(q); });
  loop(request.params,function(i,q){ params.push(q); });
  loop(headerDictionary,function(key,value){ params.push(new QueryItem(key,value)); });
  params = params.map(function(q){ return new QueryItem(encodeURIComponent(q.key),encodeURIComponent(q.value)); });
  params.sort(function(p,q){ return (p.key < q.key) ? (-1) : 1 });
  var paramString = params.map(function(q){ return q.key + "=" + q.value }).join("&");
  var baseString = method.toUpperCase() + "&" + encodeURIComponent(url) + "&" + encodeURIComponent(paramString);
  var signingKey = this.consumerSecret + "&" + fallback(tokenSecret,"");
  return b64_hmac_sha1(signingKey,baseString);
}.bind(Twitter);

Twitter.getRequestToken = function(res,rej) {
  var r = request("POST","https://api.twitter.com/oauth/request_token");
  var headerDictionary = this.generateHeaderDictionaryWithSignature(r);
  var authHeader = this.generateOAuthHeader(headerDictionary);
  r.setHeader("Authorization",authHeader).onLoad(res).onError(rej).send();
}.bind(Twitter);

Twitter.getAccessToken = function(verifier,requestToken,tokenSecret,res,rej) {
  var r = request("POST","https://api.twitter.com/oauth/access_token");
  var headerDictionary = this.generateHeaderDictionaryWithSignature(r,requestToken,tokenSecret,{oauth_verifier:verifier});
  var authHeader = this.generateOAuthHeader(headerDictionary);
  r.setHeader("Authorization",authHeader).onLoad(res).onError(rej).send();
}.bind(Twitter);

Twitter.verifyAccessToken = function(accessToken,tokenSecret,res,rej) {
  var r = request("GET","https://api.twitter.com/1.1/account/verify_credentials.json","json");
  var headerDictionary = this.generateHeaderDictionaryWithSignature(r,accessToken,tokenSecret);
  var authHeader = this.generateOAuthHeader(headerDictionary);
  r.setHeader("Authorization",authHeader).onLoad(res).onError(rej).send();
}.bind(Twitter);

Twitter.getEndpoint = function(endpoint,params,accessToken,tokenSecret,res,rej) {
  var url = "https://api.twitter.com/1.1/" + endpoint + ".json";
  var r = request("GET",url,"json");
  r.setParams(params);
  var headerDictionary = this.generateHeaderDictionaryWithSignature(r,accessToken,tokenSecret);
  var authHeader = this.generateOAuthHeader(headerDictionary);
  r.setHeader("Authorization",authHeader);
  r.onLoad(res).onError(rej).send();
}.bind(Twitter);

Twitter.streamUserFeed = function(params,accessToken,tokenSecret,res,rej) {
  var url = "https://userstream.twitter.com/1.1/user.json";
  var r = request("GET","https://userstream.twitter.com/1.1/user.json");
  r.setParams(params);
  var headerDictionary = this.generateHeaderDictionaryWithSignature(r,accessToken,tokenSecret);
  var authHeader = this.generateOAuthHeader(headerDictionary);
  r.setHeader("Authorization",authHeader);
  r.onData(res).onError(rej).send();
}.bind(Twitter);

Twitter.oEmbed = function(url,res,rej) {
  request("GET","https://publish.twitter.com/oembed","json").setParam("url",url).onLoad(res).onError(rej).send();
}.bind(Twitter);

module.exports = {
	QueryItem,
	URLComponents,
  RequestFrontEndHelpers,
  RequestBackEndHelpers,
	RequestHelpers,
  Request,
	request,
	Twitter
};