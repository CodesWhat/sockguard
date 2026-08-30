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

type catalogRuleMachine struct {
	program *syntax.Prog
	action  string
}

type catalogReachabilityBudget struct {
	states      int
	transitions int
}

// firstAllowedCatalogPath returns a concrete route in the catalog shape whose
// first matching rule allows it. Catalog occurrences of "sockguard-test" are
// non-empty resource-identifier segments. The search operates on the exact
// regular languages accepted by Sockguard's glob dialect instead of guessing
// a finite list of identifiers.
//
// The DFA product of several regular languages can be exponential in the
// number of rules. Startup work is therefore capped. Exhausting a cap returns
// indeterminate, which callers treat as exposed and fail closed rather than
// letting an unproved allow rule bypass an acknowledgment.
func firstAllowedCatalogPath(method, catalogPath string, rules []config.RuleConfig) (string, catalogReachability) {
	catalog, err := compileCatalogMachine(catalogPath)
	if err != nil {
		return catalogPath, catalogReachabilityIndeterminate
	}
	totalInstructions := len(catalog.program.Inst)

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
		machines := make([]catalogRuleMachine, 0, i+2)
		machines = append(machines, catalog)
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

func compileCatalogMachine(catalogPath string) (catalogRuleMachine, error) {
	const identifier = `(?:[^/.][^/]*|\.[^/.][^/]*|\.\.[^/]+)`
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

// catalogAllowWitness receives catalog first, every rule earlier than the
// target allow next, and the target allow last. It finds a string accepted by
// the catalog and target but by none of the earlier rules, which is precisely
// first-match reachability for that allow.
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
