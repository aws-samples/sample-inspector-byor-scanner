// Local shim for @aws/synthetics-puppeteer.
// Provides executeStep() with logging for local SAM testing.
module.exports.executeStep = async function executeStep(stepName, fn) {
  console.log(`[Synthetics] Step started: ${stepName}`);
  try {
    const result = await fn();
    console.log(`[Synthetics] Step passed: ${stepName}`);
    return result;
  } catch (err) {
    console.error(`[Synthetics] Step failed: ${stepName}`, err.message);
    throw err;
  }
};
