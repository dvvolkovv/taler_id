'use strict';
// CJS mock for uuid (used in Jest environment)
let counter = 0;
const v4 = () => `test-uuid-${++counter}`;
const v1 = () => `test-uuid-v1-${++counter}`;
module.exports = { v4, v1 };
module.exports.default = module.exports;
