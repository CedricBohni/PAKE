// Runs the project's Python code (src/fapake) inside Pyodide, off the main thread.
// Messages in:  {id, options}         -> one protocol trace
// Messages out: {type: "status", text} while loading
//               {type: "ready", python}
//               {id, ok: true, trace} | {id, ok: false, error}

const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v0.29.3/full/";
const FILES = ["__init__.py", "modmath.py", "rss.py", "ot.py", "ic.py", "protocol.py", "trace.py"];

importScripts(PYODIDE + "pyodide.js");

const status = (text) => postMessage({ type: "status", text });

const ready = (async () => {
  status("Loading Python runtime…");
  const py = await loadPyodide({ indexURL: PYODIDE });
  status("Loading cryptography…");
  await py.loadPackage("cryptography");

  status("Loading fapake…");
  py.FS.mkdirTree("/home/pyodide/fapake");
  await Promise.all(FILES.map(async (name) => {
    const response = await fetch(new URL("fapake/" + name, self.location.href), { cache: "no-cache" });
    if (!response.ok) throw new Error(`could not load fapake/${name} (${response.status})`);
    py.FS.writeFile("/home/pyodide/fapake/" + name, await response.text());
  }));

  py.runPython("import sys; sys.path.insert(0, '/home/pyodide')");
  const run = py.runPython("from fapake.trace import run_trace_json; run_trace_json");
  const python = py.runPython("import sys; sys.version.split()[0]");
  postMessage({ type: "ready", python });
  return run;
})();

ready.catch((error) => postMessage({ type: "fatal", error: String(error) }));

self.onmessage = async ({ data }) => {
  const { id, options } = data;
  try {
    const run = await ready;
    const trace = JSON.parse(run(JSON.stringify(options)));
    postMessage({ id, ok: true, trace });
  } catch (error) {
    postMessage({ id, ok: false, error: String(error) });
  }
};
