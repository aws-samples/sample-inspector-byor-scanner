// Local shim replacing the Synthetics Layer's cw-synthetics.js bootstrap.
// Routes to the handler specified in the event payload (or defaults to index.handler).
exports.handler = async (event) => {
  const handlerName = (event && event.customerCanaryHandlerName) || 'index.handler';
  const [file, fn] = handlerName.split('.');
  const mod = require(`./${file}`);
  return mod[fn]();
};
