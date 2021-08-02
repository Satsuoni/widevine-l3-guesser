import WasmDsp from "../wasm/wasm_gsr.js";
var Wdsp=null;
var _freeStr, stringToUTF8, writeArrayToMemory, UTF8ToString, stackSave, stackRestore, stackAlloc;
function getCFunc(ident) {
  return Wdsp[`_${ident}`]; // closure exported function
}

function scall (ident, returnType, argTypes, args, opts) {
  const toC = {
    string (str) {
      let ret = 0;
      if (str !== null && str !== undefined && str !== 0) {
        const len = (str.length << 2) + 1;
        ret = stackAlloc(len);
        stringToUTF8(str, ret, len);
      }
      return ret;
    },
    array (arr) {
      const ret = stackAlloc(arr.length);
      writeArrayToMemory(arr, ret);
      return ret;
    }
  };
  function convertReturnValue (ret) {
    if (returnType === 'string') return UTF8ToString(ret);
    if (returnType === 'boolean') return Boolean(ret);
    return ret;
  }
  const func = getCFunc(ident);
  const cArgs = [];
  let stack = 0;
  if (args) {
    for (let i = 0; i < args.length; i++) {
      const converter = toC[argTypes[i]];
      if (converter) {
        if (stack === 0) stack = stackSave();
        cArgs[i] = converter(args[i]);
      } else {
        cArgs[i] = args[i];
      }
    }
  }
  const _ret = func.apply(null, cArgs);
  const ret = convertReturnValue(_ret);
  _freeStr(_ret);
  if (stack !== 0) stackRestore(stack);
  return ret;
}

function swrap (ident, returnType, argTypes, opts) {
  argTypes = argTypes || [];
  const numericArgs = argTypes.every((type) => type === 'number');
  const numericRet = returnType !== 'string';
  if (numericRet && numericArgs && !opts) {
    return getCFunc(ident);
  }
  return function () {
     
    return scall(ident, returnType, argTypes, arguments, opts);
  };
}

async function init() {
  Wdsp=await WasmDsp();
  await Wdsp.ready;
  _freeStr=Wdsp._freeStr;
stringToUTF8=Wdsp.stringToUTF8;
writeArrayToMemory=Wdsp.writeArrayToMemory;
UTF8ToString=Wdsp.UTF8ToString;
stackSave=Wdsp.stackSave;
stackRestore=Wdsp.stackRestore;
stackAlloc=Wdsp.stackAlloc;
  chrome.runtime.onMessage.addListener(onRuntimeMessage);
}
function decode(val,sendResponse)
{
  var tryUsingDecoder = swrap('tryUsingDecoder', 'string', ['string']); 
  var res=tryUsingDecoder(val);
  sendResponse({value:res});
}
function onRuntimeMessage(message, _sender, sendResponse) {
  if (message.name !== "dec") return;
  if(!message.value) return;
  if(Wdsp==null)
  {
      init().then(()=>{decode(message.value,sendResponse)});
  }
  else
  {
      decode(message.value,sendResponse);
  }

}

init();
