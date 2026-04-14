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

export interface CompiledRule extends Rule {
  matcher: RegExp;
  matchReason: string;
  normalizedMethod: string;
}

const API_VERSION_PREFIX = /^\/v\d+(\.\d+)?\//;
const ESCAPABLE_REGEX_CHAR = /[.*+?^${}()|[\]\\]/g;
const compiledRulesCache = new WeakMap<Rule[], CompiledRule[]>();
const escapedCharCache = new Map();

function normalizePath(path: string): string {
  return path.replace(API_VERSION_PREFIX, "/");
}

function escapeRegexChar(char: string): string {
  const cached = escapedCharCache.get(char);
  if (cached) {
    return cached;
  }

  const escaped = char.replace(ESCAPABLE_REGEX_CHAR, "\\$&");
  escapedCharCache.set(char, escaped);
  return escaped;
}

function globToRegex(pattern: string): RegExp {
  const chars = Array.from(pattern);
  let regex = "";
  let i = 0;
  while (i < chars.length) {
    if (i + 2 < chars.length && chars[i] === "/" && chars[i + 1] === "*" && chars[i + 2] === "*") {
      // /** matches the bare path OR /anything/deeper
      regex += "(/.*)?";
      i += 3;
    } else if (i + 1 < chars.length && chars[i] === "*" && chars[i + 1] === "*") {
      regex += ".*";
      i += 2;
    } else if (chars[i] === "*") {
      regex += "[^/]*";
      i++;
    } else {
      regex += escapeRegexChar(chars[i]);
      i++;
    }
  }
  return new RegExp(`^${regex}$`);
}

function compileRule(rule: Rule): CompiledRule {
  return {
    ...rule,
    matcher: globToRegex(rule.path),
    matchReason:
      rule.reason || (rule.action === "allow" ? "matched allow rule" : "matched deny rule"),
    normalizedMethod: rule.method.toUpperCase(),
  };
}

export function compileRules(rules: Rule[]): CompiledRule[] {
  const cached = compiledRulesCache.get(rules);
  if (cached) {
    return cached;
  }

  const compiled = rules.map(compileRule);
  compiledRulesCache.set(rules, compiled);
  return compiled;
}

export function evaluateCompiled(rules: CompiledRule[], method: string, path: string): EvalResult {
  const normalized = normalizePath(path);
  const normalizedMethod = method.toUpperCase();

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];

    // Check method
    if (rule.normalizedMethod !== "*" && rule.normalizedMethod !== normalizedMethod) {
      continue;
    }

    // Check path
    if (rule.matcher.test(normalized)) {
      return {
        action: rule.action,
        ruleIndex: i,
        reason: rule.matchReason,
      };
    }
  }

  return {
    action: "deny",
    ruleIndex: -1,
    reason: "no matching allow rule",
  };
}

export function evaluate(rules: Rule[], method: string, path: string): EvalResult {
  return evaluateCompiled(compileRules(rules), method, path);
}
