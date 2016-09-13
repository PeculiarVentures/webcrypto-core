# webcrypto-core
We have created a number of WebCrypto polyfills including: [node-webcrypto-ossl](https://github.com/PeculiarVentures/node-webcrypto-ossl), [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11), and [webcrypto-liner](https://github.com/PeculiarVentures/webcrypto-liner).  `webcrypto-core` was designed to be a common layer to be used by all of these libraries for input validation.

Unless you intend to create a WebCrypto polyfill this library is probably not useful to you.

## Dependencies

Install all dependencies
```
npm install
```

> NOTE: `npm install` command downloads and installs modules to local folder. 
> You can install all dependancies globally 

typescript
```
npm install typescript --global
```

uglifyjs
```
npm install uglifyjs --global
```

mocha
```
npm install mocha --global
```

## Compilation 
Compile the source code using the following command:
```
npm run build
```
> NOTE: Command creates `webcrypto-core.js` and `webcrypto-core.min.js` files in `build` folder

Compile the source code with declaration using the next command:
```
tsc --declaration
```

## Minify
```
npm run minify
```

## Test
```
npm test
```

## Lib size

| Files                   | Size       |
|-------------------------|------------|
| webcrypto-core.js       | 58Kb       |
| webcrypto-core.min.js   | 25Kb       |