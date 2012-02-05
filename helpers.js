var foreach = function(obj, callback) {
  for(var k in obj) {
    if(obj.hasOwnProperty(k)) {
      callback(k, obj[k]);
    }
  }
};