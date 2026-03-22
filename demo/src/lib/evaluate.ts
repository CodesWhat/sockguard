export type Action = "allow" | "deny";

export interface Rule {
  method: string;
  path: string;
  action: Action;
  reason?: string;
}

export interface EvalResult {
  action: Action;
  ruleIndex: number;
  reason: string;
}

const API_VERSION_PREFIX = /^\/v\d+(\.\d+)?\//;

function normalizePath(path: string): string {
  return path.replace(API_VERSION_PREFIX, "/");
}

function globToRegex(pattern: string): RegExp {
  let regex = "";
  let i = 0;
  while (i < pattern.length) {
    if (i + 1 < pattern.length && pattern[i] === "*" && pattern[i + 1] === "*") {
      regex += ".*";
      i += 2;
    } else if (pattern[i] === "*") {
      regex += "[^/]*";
      i++;
    } else {
      regex += pattern[i].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      i++;
    }
  }
  return new RegExp(`^${regex}$`);
}

export function evaluate(rules: Rule[], method: string, path: string): EvalResult {
  const normalized = normalizePath(path);

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];

    // Check method
    if (rule.method !== "*" && rule.method.toUpperCase() !== method.toUpperCase()) {
      continue;
    }

    // Check path
    const pattern = globToRegex(rule.path);
    if (pattern.test(normalized)) {
      return {
        action: rule.action,
        ruleIndex: i,
        reason: rule.reason || (rule.action === "allow" ? "matched allow rule" : "matched deny rule"),
      };
    }
  }

  return {
    action: "deny",
    ruleIndex: -1,
    reason: "no matching allow rule",
  };
}
