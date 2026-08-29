const fs = require("node:fs");

const offsetPath = process.env.TT_CLOCK_OFFSET_FILE;
if (!offsetPath) {
  throw new Error("TT_CLOCK_OFFSET_FILE is required");
}

const hostNow = Date.now.bind(Date);

Date.now = () => {
  const offsetSeconds = Number.parseInt(fs.readFileSync(offsetPath, "utf8").trim(), 10);
  if (!Number.isFinite(offsetSeconds)) {
    throw new Error(`invalid clock offset in ${offsetPath}`);
  }
  return hostNow() + offsetSeconds * 1000;
};
