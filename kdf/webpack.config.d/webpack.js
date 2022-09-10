const path = require('path');
config.resolve.modules.push(path.resolve(__dirname, 'node_modules'));
config.resolve.fallback = {path: false, fs: false, crypto: false};
config.module.noParse = /\.wasm$/;
config.module.rules.push({test: /\.wasm$/, loader: 'base64-loader', type: 'javascript/auto'});
