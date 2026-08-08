// Front-end for the benchmark fixture app.
// BENCHMARK FIXTURE — the unsafe patterns below are planted deliberately.

const crypto = require("crypto");
const { exec, execFile } = require("child_process");

// --- planted: must be detected -------------------------------------------- //
function renderUnsafe(el, data) {
  el.innerHTML = data.html;
  return eval(data.expression);
}

function convertUnsafe(dir) {
  exec("convert " + dir + "/in.png out.png");
}

function encryptUnsafe(plaintext, password) {
  return crypto.createCipher("aes-256-cbc", password);
}

function inflateUnsafe(payload) {
  return unserialize(payload);
}

// --- decoys: must NOT be detected ------------------------------------------ //
function renderSafe(el, data) {
  // textContent never parses its value as markup.
  el.textContent = data.text;
}

function convertSafe(dir) {
  // Argument array, no shell involved.
  execFile("convert", [dir + "/in.png", "out.png"]);
}

function encryptSafe(plaintext, key) {
  const iv = crypto.randomBytes(16);
  return crypto.createCipheriv("aes-256-cbc", key, iv);
}

function inflateSafe(payload) {
  return JSON.parse(payload);
}

function describeEval() {
  // The literal word in a string is not a call site.
  return "avoid eval() in application code";
}

module.exports = {
  renderUnsafe, convertUnsafe, encryptUnsafe, inflateUnsafe,
  renderSafe, convertSafe, encryptSafe, inflateSafe, describeEval,
};
