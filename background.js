function Queue() {
  var queue = [];

  this.getLength = function() {
    return queue.length;
  }

  this.getArray = function() {
    return queue;
  }

  this.setArray = function(value) {
    queue = value;
  }

  this.isEmpty = function() {
    return (queue.length == 0);
  }

  this.enqueue = function(item) {
    queue.push(item);
  }

  this.dequeue = function() {
    if (queue.length == 0) return undefined;

    var item = queue[0];
    queue = queue.slice(1);
    return item;
  }

  this.clear = function() {
    queue = [];
  }
}

function OAuthHandler(consumer_key, consumer_secret, token, token_secret) {
  var consumer_key = consumer_key;
  var consumer_secret = consumer_secret;
  var token = token;
  var token_secret = token_secret;

  this.oauthEscape = function(string) {
    if (string === undefined) {
      return "";
    }

    return encodeURIComponent(string).
      replace(/\!/g, "%21").
      replace(/\*/g, "%2A").
      replace(/'/g, "%27").
      replace(/\(/g, "%28").
      replace(/\)/g, "%29");
  };

  this.getNonce = function(length) {
    var nonce_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if (length === undefined) {
      length = 8;
    }
    var result = "";
    var cLength = nonce_chars.length;
    for (var i = 0; i < length; i++) {
      var rnum = Math.floor(Math.random() * cLength);
      result += nonce_chars.substring(rnum, rnum + 1);
    }
    return result;
  };

  this.getTimestamp = function() {
    var d = new Date();
    return Math.floor(d.getTime() / 1000);
  };

  this.getParametersString = function(parameters) {
    var result = '';
    for (var p in parameters)
    {
      result += p + '=' + this.oauthEscape(parameters[p]) + '&';
    }
    return result.substring(0, result.length - 1);
  };

  // heavily optimized and compressed version of http://pajhome.org.uk/crypt/md5/sha1.js
  // _p = b64pad, _z = character size; not used here but I left them available just in case
  this.b64_hmac_sha1 = function(k, d, _p, _z) {
    if(!_p){_p='=';}if(!_z){_z=8;}function _f(t,b,c,d){if(t<20){return(b&c)|((~b)&d);}if(t<40){return b^c^d;}if(t<60){return(b&c)|(b&d)|(c&d);}return b^c^d;}function _k(t){return(t<20)?1518500249:(t<40)?1859775393:(t<60)?-1894007588:-899497514;}function _s(x,y){var l=(x&0xFFFF)+(y&0xFFFF),m=(x>>16)+(y>>16)+(l>>16);return(m<<16)|(l&0xFFFF);}function _r(n,c){return(n<<c)|(n>>>(32-c));}function _c(x,l){x[l>>5]|=0x80<<(24-l%32);x[((l+64>>9)<<4)+15]=l;var w=[80],a=1732584193,b=-271733879,c=-1732584194,d=271733878,e=-1009589776;for(var i=0;i<x.length;i+=16){var o=a,p=b,q=c,r=d,s=e;for(var j=0;j<80;j++){if(j<16){w[j]=x[i+j];}else{w[j]=_r(w[j-3]^w[j-8]^w[j-14]^w[j-16],1);}var t=_s(_s(_r(a,5),_f(j,b,c,d)),_s(_s(e,w[j]),_k(j)));e=d;d=c;c=_r(b,30);b=a;a=t;}a=_s(a,o);b=_s(b,p);c=_s(c,q);d=_s(d,r);e=_s(e,s);}return[a,b,c,d,e];}function _b(s){var b=[],m=(1<<_z)-1;for(var i=0;i<s.length*_z;i+=_z){b[i>>5]|=(s.charCodeAt(i/8)&m)<<(32-_z-i%32);}return b;}function _h(k,d){var b=_b(k);if(b.length>16){b=_c(b,k.length*_z);}var p=[16],o=[16];for(var i=0;i<16;i++){p[i]=b[i]^0x36363636;o[i]=b[i]^0x5C5C5C5C;}var h=_c(p.concat(_b(d)),512+d.length*_z);return _c(o.concat(h),512+160);}function _n(b){var t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",s='';for(var i=0;i<b.length*4;i+=3){var r=(((b[i>>2]>>8*(3-i%4))&0xFF)<<16)|(((b[i+1>>2]>>8*(3-(i+1)%4))&0xFF)<<8)|((b[i+2>>2]>>8*(3-(i+2)%4))&0xFF);for(var j=0;j<4;j++){if(i*8+j*6>b.length*32){s+=_p;}else{s+=t.charAt((r>>6*(3-j))&0x3F);}}}return s;}function _x(k,d){return _n(_h(k,d));}return _x(k,d);
  };

  this.generateSignature = function(method, url, parameters) {
    var secretKey = consumer_secret + '&' + token_secret;
    var sigString = this.oauthEscape(method) + '&' + this.oauthEscape(url) + '&' +
      this.oauthEscape(this.getParametersString(parameters));
    return this.b64_hmac_sha1(secretKey, sigString);
  };

  this.getHeaderString = function(parameters) {
    var result = 'OAuth realm=""';
    for (var p in parameters)
    {
      if (!p.match(/^oauth/)) {
        continue;
      }
      result += ', ' + p + '="' + this.oauthEscape(parameters[p]) + '"';
    }
    return result;
  };

  this.getParameters = function() {
    return {
      "oauth_consumer_key" : consumer_key,
      "oauth_nonce" : this.getNonce(),
      "oauth_signature_method" : "HMAC-SHA1",
      "oauth_timestamp" : this.getTimestamp(),
      "oauth_token" : token,
      "oauth_version" : "1.0"
    };
  }
};

function SourceOfTits() {
  var timer = null;
  var queue = new Queue();
  var oauth = null;

  var settings = {
    consumer_key : '',
    consumer_secret : '',
    access_key : '',
    access_secret : '',
    interval : 30,
  };

  this.loadSettings = function() {
    foreach(settings, function(k, v) {
      var savedValue = localStorage[k];
      settings[k] = (savedValue) ? savedValue : v;
    });

    if (settings.consumer_key && settings.consumer_secret && settings.access_key && settings.access_secret) {
      oauth = new OAuthHandler(
        settings.consumer_key,
        settings.consumer_secret,
        settings.access_key,
        settings.access_secret
      );
      return true;
    } else {
      oauth = null;
      return false;
    }
  }

  this.start = function() {
    if (!timer) {
      if (this.loadSettings()) {
        var bind = this;
        timer = window.setInterval(
          function() {
            bind.process();
          }, 
          settings.interval * 60 * 1000);

        this.process();
        
        console.log("Process started at " + this.now());
      }
    }
  }

  this.stop = function() {
    if (timer) {
      window.clearInterval(timer);
      timer = null;

      console.log("Process stopped at " + this.now());
    }
  }

  this.now = function() {
    var currentTime = new Date();
    var month = currentTime.getMonth() + 1;
    var day = currentTime.getDate();
    var year = currentTime.getFullYear();
    var hours = currentTime.getHours();
    var minutes = currentTime.getMinutes();
    var seconds = currentTime.getSeconds();
    if (minutes < 10) { minutes = "0" + minutes; }
    if (seconds < 10) { seconds = "0" + seconds; }
    if (day < 10) { day = "0" + day; }
    if (month < 10) { month = "0" + month; }
    return day + "." + month + "." + year + " " + hours + ":" + minutes + ":" + seconds;
  }

  this.save = function() {
    localStorage['queue'] = queue.getArray().join("\n");
  }

  this.load = function() {
    if (localStorage['queue']) {
      queue.setArray(localStorage['queue'].split("\n"));
    } else {
      queue.clear();
    }
  }

  this.count = function() {
    return queue.getLength();
  }

  this.clear = function() {
    queue.clear();
    delete localStorage['queue'];
  }

  this.enqueue = function(value) {
    queue.enqueue(value);
    this.save();

    console.log(this.now() + " : [" + queue.getLength() + "] <<< " + value);
  }

  this.process = function() {
    if (!queue.isEmpty() && oauth) {
      var method = 'POST';
      var url = 'https://api.twitter.com/1/statuses/update.json';
      
      var status = queue.dequeue();
      this.save();

      console.log(this.now() + " : [" + queue.getLength() + "] >>> " + status);

      var parameters = oauth.getParameters();
      parameters['status'] = status;
      var oauth_signature = oauth.generateSignature(method, url, parameters);
      parameters["oauth_signature"] = oauth_signature;

      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function(data) {};
      xhr.open(method, url, true);
      xhr.setRequestHeader('Authorization', oauth.getHeaderString(parameters));
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
      xhr.send('status=' + oauth.oauthEscape(status));
    }
  }
};



function getClickHandler() {
  return function(info, tab) {
    tits.enqueue(info.srcUrl);
  };
};

chrome.contextMenus.create({
  "title" : "Source of tits",
  "type" : "normal",
  "contexts" : ["image"],
  "onclick" : getClickHandler()
});

var tits = new SourceOfTits();
tits.loadSettings();
tits.load();