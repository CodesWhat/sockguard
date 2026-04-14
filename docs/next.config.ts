import path from "node:path";
import { fileURLToPath } from "node:url";
import nextra from "nextra";

const withNextra = nextra({});
const workspaceRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

export default withNextra({
  output: "export",
  turbopack: {
    root: workspaceRoot,
  },
});
