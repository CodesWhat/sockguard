package cmd

import (
	"encoding/binary"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/glob"
)

const (
	maxCatalogReachabilityInstructions = 4096
	maxCatalogReachabilityStates       = 8192
	maxCatalogReachabilityTransitions  = 1 << 18
)

type catalogReachability uint8

const (
	catalogUnreachable catalogReachability = iota
	catalogReachable
	catalogReachabilityIndeterminate
)

// catalogIdentifierShape is the language a catalog template's "sockguard-test"
// placeholder stands for.
type catalogIdentifierShape uint8

const (
	// catalogIdentifierSegment is one non-empty clean segment, the shape of
	// upstream's {id} and {name} route variables.
	catalogIdentifierSegment catalogIdentifierShape = iota
	// catalogIdentifierPath is a non-empty run of clean segments, the shape of
	// upstream's {name:.*} route variables for registry-qualified image,
	// plugin, and manifest names.
	catalogIdentifierPath
	// catalogIdentifierRoutePath is catalogIdentifierPath as gorilla/mux
	// resolves it, which is the view Podman routes on: `.*` also matches the
	// empty string and swallows a trailing slash, so the identifier may be
	// absent altogether or end on the empty segment that slash leaves behind.
	// filter.NormalizePodmanRoutePath preserves exactly that segment, and
	// filter.evaluateRequestPolicy then decides the request on the decoded
	// path AND on this route view.
	//
	// The empty segment is security-significant wherever an action route is
	// registered under the same prefix as a catch-all:
	// POST /libpod/images/scp/{name}/push is the image-push route, but
	// POST /libpod/images/scp/{name}/push/ misses it and falls through to the
	// image-SCP catch-all (filter.isLibpodImageScpRoutePath). Spelling the
	// catalog entry with this shape puts that request in the catalog
	// language, while the entry's exclusions — spelled without the empty
	// segment — keep removing the bare action routes that really do belong to
	// the earlier handler. The absent identifier matters for the same reason:
	// POST /libpod/images/scp/ reaches the catch-all with an empty name, so a
	// rule written for a sibling route (POST /libpod/images/* covering pull,
	// load and import, say) must not be able to admit it unnoticed.
	//
	// It describes the identifier of a placeholder that ends its template,
	// which is where both route-view entries spell it. Mid-template it would
	// also admit a doubled slash, a shape no normalized route view has.
	catalogIdentifierRoutePath
)

type catalogRuleMachine struct {
	program *syntax.Prog
	action  string
}

type catalogReachabilityBudget struct {
	states      int
	transitions int
}

// firstAllowedCatalogPath returns a concrete route in the catalog shape whose
// first matching rule allows it. Catalog occurrences of "sockguard-test" stand
// for one non-empty clean segment, a non-empty run of them, or a route view's
// resolution of that run (absent, or ending on the empty segment a trailing
// slash keeps), according to identifierShape. The search operates on the exact
// regular languages accepted by Sockguard's glob dialect instead of guessing a
// finite list of identifiers.
//
// A catalogIdentifierRoutePath witness that ends on the empty segment is a
// request spelling, not a decoded path: filter.evaluateRequestPolicy requires
// the decoded view to allow as well, and this search does not model that
// second view. The verdict therefore over-reports rather than under-reports on
// that shape, which is the direction the caller can absorb — allowedCatalogPaths
// re-runs every witness through the production evaluator and falls back to the
// stable catalog spelling when it does not survive.
//
// The DFA product of several regular languages can be exponential in the
// number of rules. Startup work is therefore capped. Exhausting a cap returns
// indeterminate, which callers treat as exposed and fail closed rather than
// letting an unproved allow rule bypass an acknowledgment.
func firstAllowedCatalogPath(method, catalogPath string, identifierShape catalogIdentifierShape, exclusions []catalogPathExclusion, rules []config.RuleConfig) (string, catalogReachability) {
	catalog, err := compileCatalogMachine(catalogPath, identifierShape)
	if err != nil {
		return catalogPath, catalogReachabilityIndeterminate
	}
	totalInstructions := len(catalog.program.Inst)
	catalogMachines := []catalogRuleMachine{catalog}
	for _, exclusion := range exclusions {
		machine, err := compileCatalogMachine(exclusion.path, exclusion.identifierShape)
		if err != nil {
			return catalogPath, catalogReachabilityIndeterminate
		}
		totalInstructions += len(machine.program.Inst)
		if totalInstructions > maxCatalogReachabilityInstructions {
			return catalogPath, catalogReachabilityIndeterminate
		}
		catalogMachines = append(catalogMachines, machine)
	}

	lastAllow := -1
	for i := range rules {
		if rules[i].Action == "allow" && configuredRuleMatchesMethod(rules[i].Match.Method, method) {
			lastAllow = i
		}
	}
	if lastAllow < 0 {
		return "", catalogUnreachable
	}

	applicable := make([]catalogRuleMachine, 0, lastAllow+1)
	for _, rule := range rules[:lastAllow+1] {
		if !configuredRuleMatchesMethod(rule.Match.Method, method) {
			continue
		}
		machine, err := compileCatalogRuleMachine(rule.Match.Path, rule.Action)
		if err != nil {
			return catalogPath, catalogReachabilityIndeterminate
		}
		totalInstructions += len(machine.program.Inst)
		if totalInstructions > maxCatalogReachabilityInstructions {
			return catalogPath, catalogReachabilityIndeterminate
		}
		applicable = append(applicable, machine)
	}

	budget := catalogReachabilityBudget{}
	for i := range applicable {
		if applicable[i].action != "allow" {
			continue
		}
		machines := make([]catalogRuleMachine, 0, len(catalogMachines)+i+1)
		machines = append(machines, catalogMachines...)
		machines = append(machines, applicable[:i]...)
		machines = append(machines, applicable[i])
		witness, result := catalogAllowWitness(machines, &budget)
		if result != catalogUnreachable {
			return witness, result
		}
	}

	return "", catalogUnreachable
}

func configuredRuleMatchesMethod(configured, method string) bool {
	for _, candidate := range splitMethods(configured) {
		if candidate == "*" || strings.EqualFold(candidate, method) {
			return true
		}
	}
	return false
}

func compileCatalogMachine(catalogPath string, identifierShape catalogIdentifierShape) (catalogRuleMachine, error) {
	const segment = `(?:[^/.][^/]*|\.[^/.][^/]*|\.\.[^/]+)`
	identifier := segment
	if identifierShape != catalogIdentifierSegment {
		identifier = segment + `(?:/` + segment + `)*`
	}
	if identifierShape == catalogIdentifierRoutePath {
		// The optional trailing "/" is the empty final segment a route view
		// keeps, and the outer option is `.*` matching the empty string, which
		// is how the bare route with no identifier at all reaches the
		// catch-all handler. See catalogIdentifierRoutePath.
		identifier = `(?:` + identifier + `/?)?`
	}
	parts := strings.Split(catalogPath, "sockguard-test")
	var expression strings.Builder
	for i, part := range parts {
		if i > 0 {
			expression.WriteString(identifier)
		}
		expression.WriteString(regexp.QuoteMeta(part))
	}
	program, err := compileReachabilityProgram(expression.String())
	return catalogRuleMachine{program: program}, err
}

func compileCatalogRuleMachine(pattern, action string) (catalogRuleMachine, error) {
	expression := glob.ToRegexString(pattern)
	switch {
	case !strings.Contains(pattern, "*"):
		expression = regexp.QuoteMeta(pattern)
	case pattern == "/**":
		// filter.CompiledRule's match-all fast path includes newlines.
		expression = `(?s:.*)`
	case strings.HasSuffix(pattern, "/**") && !strings.Contains(pattern[:len(pattern)-3], "*"):
		// Mirror filter.matchTrailingDoubleStar, including its exact-prefix case
		// and its byte-unrestricted descendant suffix.
		prefix := strings.TrimSuffix(pattern, "/**")
		expression = regexp.QuoteMeta(prefix) + `(?:/(?s:.*))?`
	case !strings.Contains(pattern, "**"):
		// filter.pathMatcherSegmentGlob strips one optional leading slash from
		// both the pattern and request path. Preserve the catalog's leading slash
		// while compiling the remaining segment glob so the automata agree.
		expression = "/" + glob.ToRegexString(strings.TrimPrefix(pattern, "/"))
	}
	program, err := compileReachabilityProgram(expression)
	return catalogRuleMachine{program: program, action: action}, err
}

func compileReachabilityProgram(expression string) (*syntax.Prog, error) {
	parsed, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		return nil, err
	}
	return syntax.Compile(parsed.Simplify())
}

type reachabilityState struct {
	machines [][]uint64
	witness  string
}

// catalogAllowWitness receives the positive catalog first, catalog exclusions
// and every rule earlier than the target allow next, and the target allow last.
// It finds a string accepted by the catalog and target but by none of the
// exclusions or earlier rules, which is precisely first-match reachability for
// that allow on the upstream route language.
func catalogAllowWitness(machines []catalogRuleMachine, budget *catalogReachabilityBudget) (string, catalogReachability) {
	start := reachabilityState{machines: make([][]uint64, len(machines))}
	for i := range machines {
		start.machines[i] = reachabilityStart(machines[i].program)
	}

	queue := []reachabilityState{start}
	seen := map[string]struct{}{reachabilityStateKey(start.machines): {}}
	for head := 0; head < len(queue); head++ {
		current := queue[head]
		if catalogAllowAccepts(machines, current.machines) {
			return current.witness, catalogReachable
		}

		for _, candidate := range reachabilityCandidateRunes(machines, current.machines) {
			budget.transitions++
			if budget.transitions > maxCatalogReachabilityTransitions {
				return "", catalogReachabilityIndeterminate
			}
			nextMachines := make([][]uint64, len(machines))
			for i := range machines {
				nextMachines[i] = reachabilityAdvance(machines[i].program, current.machines[i], candidate)
			}
			if reachabilityEmpty(nextMachines[0]) {
				continue
			}
			key := reachabilityStateKey(nextMachines)
			if _, ok := seen[key]; ok {
				continue
			}
			budget.states++
			if budget.states > maxCatalogReachabilityStates {
				return "", catalogReachabilityIndeterminate
			}
			seen[key] = struct{}{}
			queue = append(queue, reachabilityState{
				machines: nextMachines,
				witness:  current.witness + string(candidate),
			})
		}
	}

	return "", catalogUnreachable
}

func catalogAllowAccepts(machines []catalogRuleMachine, states [][]uint64) bool {
	last := len(machines) - 1
	if !reachabilityAccepts(machines[0].program, states[0]) || !reachabilityAccepts(machines[last].program, states[last]) {
		return false
	}
	for i := 1; i < last; i++ {
		if reachabilityAccepts(machines[i].program, states[i]) {
			return false
		}
	}
	return true
}

func reachabilityStart(program *syntax.Prog) []uint64 {
	state := make([]uint64, (len(program.Inst)+63)/64)
	reachabilityAddClosure(program, state, program.Start)
	return state
}

func reachabilityAdvance(program *syntax.Prog, current []uint64, candidate rune) []uint64 {
	next := make([]uint64, len(current))
	for pc, instruction := range program.Inst {
		if !reachabilityHas(current, pc) || !reachabilityInstructionMatches(&instruction, candidate) {
			continue
		}
		reachabilityAddClosure(program, next, int(instruction.Out))
	}
	return next
}

func reachabilityAddClosure(program *syntax.Prog, state []uint64, start int) {
	stack := []int{start}
	for len(stack) > 0 {
		last := len(stack) - 1
		pc := stack[last]
		stack = stack[:last]
		if pc < 0 || pc >= len(program.Inst) || reachabilityHas(state, pc) {
			continue
		}
		reachabilitySet(state, pc)
		instruction := program.Inst[pc]
		switch instruction.Op {
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, int(instruction.Out), int(instruction.Arg))
		case syntax.InstCapture, syntax.InstNop, syntax.InstEmptyWidth:
			stack = append(stack, int(instruction.Out))
		}
	}
}

func reachabilityInstructionMatches(instruction *syntax.Inst, candidate rune) bool {
	switch instruction.Op {
	case syntax.InstRune, syntax.InstRune1:
		return instruction.MatchRune(candidate)
	case syntax.InstRuneAny:
		return true
	case syntax.InstRuneAnyNotNL:
		return candidate != '\n'
	default:
		return false
	}
}

func reachabilityCandidateRunes(machines []catalogRuleMachine, states [][]uint64) []rune {
	candidates := map[rune]struct{}{
		'a': {}, 'b': {}, '0': {}, '-': {}, '_': {}, '.': {}, '/': {}, '\n': {},
	}
	for i := range machines {
		for pc, instruction := range machines[i].program.Inst {
			if !reachabilityHas(states[i], pc) {
				continue
			}
			switch instruction.Op {
			case syntax.InstRune, syntax.InstRune1:
				for j := 0; j < len(instruction.Rune); j += 2 {
					lo := instruction.Rune[j]
					hi := lo
					if j+1 < len(instruction.Rune) {
						hi = instruction.Rune[j+1]
					}
					addReachabilityBoundaryRunes(candidates, lo)
					addReachabilityBoundaryRunes(candidates, hi)
				}
			case syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
				addReachabilityBoundaryRunes(candidates, 0)
				addReachabilityBoundaryRunes(candidates, unicode.MaxRune)
			}
		}
	}

	preferred := []rune{'a', 'b', '0', '-', '_', '.', '/', '\n'}
	result := make([]rune, 0, len(candidates))
	for _, candidate := range preferred {
		if _, ok := candidates[candidate]; ok {
			result = append(result, candidate)
			delete(candidates, candidate)
		}
	}
	rest := make([]rune, 0, len(candidates))
	for candidate := range candidates {
		if candidate >= 0 && candidate <= unicode.MaxRune && (candidate < 0xD800 || candidate > 0xDFFF) {
			rest = append(rest, candidate)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i] < rest[j] })
	return append(result, rest...)
}

func addReachabilityBoundaryRunes(candidates map[rune]struct{}, boundary rune) {
	for _, candidate := range []rune{boundary - 1, boundary, boundary + 1} {
		if candidate >= 0 && candidate <= unicode.MaxRune && (candidate < 0xD800 || candidate > 0xDFFF) {
			candidates[candidate] = struct{}{}
		}
	}
}

func reachabilityAccepts(program *syntax.Prog, state []uint64) bool {
	for pc, instruction := range program.Inst {
		if instruction.Op == syntax.InstMatch && reachabilityHas(state, pc) {
			return true
		}
	}
	return false
}

func reachabilityEmpty(state []uint64) bool {
	for _, word := range state {
		if word != 0 {
			return false
		}
	}
	return true
}

func reachabilityStateKey(states [][]uint64) string {
	size := 0
	for _, state := range states {
		size += len(state) * 8
	}
	key := make([]byte, size)
	offset := 0
	for _, state := range states {
		for _, word := range state {
			binary.LittleEndian.PutUint64(key[offset:], word)
			offset += 8
		}
	}
	return string(key)
}

func reachabilityHas(state []uint64, pc int) bool {
	return state[pc/64]&(uint64(1)<<uint(pc%64)) != 0
}

func reachabilitySet(state []uint64, pc int) {
	state[pc/64] |= uint64(1) << uint(pc%64)
}
