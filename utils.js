
function concatUint8Arrays(arrays) {
    var totalLength = 0;
    for (var i = 0; i < arrays.length; i++) {
        totalLength += arrays[i].length;
    }

    var result = new Uint8Array(totalLength);
    var offset = 0;

    for (var i = 0; i < arrays.length; i++) {
        result.set(arrays[i], offset);
        offset += arrays[i].length;
    }

    return result;
}

function arraybufferEqual(buf1, buf2) {
  //if (buf1 === buf2) {
  //return true;
  //}

  if (buf1.byteLength !== buf2.byteLength) {
  return false;
  }

  var view1 = new DataView(buf1);
  var view2 = new DataView(buf2);

  for (let i = 0; i < buf1.byteLength; i++) {
    if (view1.getUint8(i) !== view2.getUint8(i)) {
      return false;
    }
  }

  return true;
}

function arraysEqual(a, b) {
  //if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;

  // If you don't care about the order of the elements inside
  // the array, you should sort both arrays here.
  // Please note that calling sort on an array will modify that array.
  // you might want to clone your array first.

  for (var i = 0; i < a.length; ++i) {
    if(typeof a[i] !== 'undefined' && typeof b[i] !== 'undefined' && a[i]!==null && b[i]!==null && typeof a[i].byteLength == 'number' && typeof b[i].byteLength == 'number'){
      if(arraybufferEqual(a[i],b[i])==false){
        return false;
      }
    }else{
      if(typeof a[i]=='string' && typeof b[i]=='string'){
        if (a[i] !== b[i]){
          return false;
        }
      }else if(a[i].constructor==RegExp && typeof b[i]=='string'){
        if(a[i].test(b[i])==false){
          return false;
        }
      }else if(typeof a[i]=='string' && b[i].constructor==RegExp){
        if(b[i].test(a[i])==false){
          return false;
        }
      //}else if(a[i] instanceof Object && b[i] instanceof Object && Object.keys(a[i]).length>0 && Object.keys(b[i]).length>0){
        //if(_this.objectEquals(a[i],b[i])==false){
        //	return false;
        //}
      }else{
        if (a[i] !== b[i]){
          return false;
        }
      }
      
    }
  }
  return true;
};



export {
  concatUint8Arrays,
  arraybufferEqual,
  arraysEqual
};