// Runs the C++ engine (compiled to WebAssembly) in the background, so the page
// stays responsive. Nothing leaves the browser.
importScripts("engine.js");

onmessage = async ({ data: { capture, args } }) => {
  try {
    const errors = [];
    const engine = await createEngine({ print() {}, printErr: line => errors.push(line) });
    engine.FS.writeFile("/in", new Uint8Array(capture));
    engine.callMain(["/in", "/out.pcap", ...args, "--json", "/report.json"]);
    const message = errors.join(" ").replace(/^Error: /, "");
    if (!engine.FS.analyzePath("/report.json").exists) return postMessage({ error: message || "invalid input" });
    const report = JSON.parse(engine.FS.readFile("/report.json", { encoding: "utf8" }));
    const filtered = engine.FS.readFile("/out.pcap");
    report.warning = message;
    postMessage({ report, filtered }, [filtered.buffer]);
  } catch (e) {
    postMessage({ error: "The capture could not be analyzed. It may be too large for this browser." });
  }
};
