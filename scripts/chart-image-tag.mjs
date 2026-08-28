function decodeDoubleQuoted(value, field) {
  try {
    const decoded = JSON.parse(value);
    if (typeof decoded === "string") {
      return decoded;
    }
  } catch {
    // The release metadata contract intentionally accepts only the JSON-compatible
    // subset of YAML double-quoted strings. Unsupported YAML escapes fail closed.
  }
  throw new Error("Unsupported " + field + " syntax in chart/sockguard/values.yaml");
}

function parseMappingEntry(content, field) {
  const plain = content.match(/^([A-Za-z][A-Za-z0-9_-]*)\s*:(.*)$/u);
  if (plain) {
    return { key: plain[1], value: plain[2].trim() };
  }

  const singleQuoted = content.match(/^'((?:[^']|'')*)'\s*:(.*)$/u);
  if (singleQuoted) {
    return { key: singleQuoted[1].replaceAll("''", "'"), value: singleQuoted[2].trim() };
  }

  const doubleQuoted = content.match(/^("(?:[^"\\]|\\.)*")\s*:(.*)$/u);
  if (doubleQuoted) {
    return {
      key: decodeDoubleQuoted(doubleQuoted[1], field + " key"),
      value: doubleQuoted[2].trim(),
    };
  }

  throw new Error("Unsupported " + field + " mapping syntax in chart/sockguard/values.yaml");
}

function parseStringValue(source, field) {
  const doubleQuoted = source.match(/^("(?:[^"\\]|\\.)*")\s*(?:#.*)?$/u);
  if (doubleQuoted) {
    return decodeDoubleQuoted(doubleQuoted[1], field);
  }

  const singleQuoted = source.match(/^'((?:[^']|'')*)'\s*(?:#.*)?$/u);
  if (singleQuoted) {
    return singleQuoted[1].replaceAll("''", "'");
  }

  const plain = source.match(/^([^\s#]+)\s*(?:#.*)?$/u);
  if (plain) {
    return plain[1];
  }

  throw new Error("Could not find string " + field + " in chart/sockguard/values.yaml");
}

export function extractChartImageConfig(source) {
  const lines = String(source ?? "").split(/\r?\n/u);
  let imageBlockSeen = false;
  let inImageBlock = false;
  let childIndent;
  const imageValues = new Map();

  for (const line of lines) {
    const content = line.trimStart();
    if (content === "" || content.startsWith("#")) {
      continue;
    }
    const indent = line.length - content.length;

    if (indent === 0) {
      inImageBlock = false;
      const entry = parseMappingEntry(content, "top-level");
      if (entry.key !== "image") {
        continue;
      }
      if (imageBlockSeen) {
        throw new Error("Duplicate top-level image block in chart/sockguard/values.yaml");
      }
      if (entry.value !== "" && !entry.value.startsWith("#")) {
        throw new Error("image must be a block mapping in chart/sockguard/values.yaml");
      }
      imageBlockSeen = true;
      inImageBlock = true;
      childIndent = undefined;
      continue;
    }

    if (!inImageBlock) {
      continue;
    }

    childIndent ??= indent;
    if (indent !== childIndent) {
      continue;
    }

    const entry = parseMappingEntry(content, "image");
    if (entry.key !== "repository" && entry.key !== "tag") {
      continue;
    }
    if (imageValues.has(entry.key)) {
      throw new Error("Duplicate image." + entry.key + " in chart/sockguard/values.yaml");
    }
    imageValues.set(entry.key, parseStringValue(entry.value, "image." + entry.key));
  }

  if (!imageBlockSeen) {
    throw new Error("Could not find mapping image in chart/sockguard/values.yaml");
  }
  for (const field of ["repository", "tag"]) {
    if (!imageValues.has(field)) {
      throw new Error("Could not find string image." + field + " in chart/sockguard/values.yaml");
    }
  }

  return {
    repository: imageValues.get("repository"),
    tag: imageValues.get("tag"),
  };
}

export function extractChartImageTag(source) {
  return extractChartImageConfig(source).tag;
}
