const fs = require("node:fs");

const offsetPath = process.env.TT_CLOCK_OFFSET_FILE;
if (!offsetPath) {
  throw new Error("TT_CLOCK_OFFSET_FILE is required");
}

const hostNow = Date.now.bind(Date);

Date.now = () => {
  const rawOffset = fs.readFileSync(offsetPath, "utf8").trim();
  if (!/^[+-]?\d+$/.test(rawOffset)) {
    throw new Error(`invalid clock offset in ${offsetPath}`);
  }
  const offsetSeconds = Number(rawOffset);
  if (!Number.isSafeInteger(offsetSeconds)) {
    throw new Error(`invalid clock offset in ${offsetPath}`);
  }
  return hostNow() + offsetSeconds * 1000;
};
