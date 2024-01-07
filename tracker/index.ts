const libcFunctions = Process
    .getModuleByName('libc.so')
    .enumerateExports()
    .filter(exported => exported.type === 'function')
    .map(exported => exported.name)
console.log(libcFunctions)
