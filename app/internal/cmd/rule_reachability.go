package cmd

import (
	"encoding/binary"
	"math/bits"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/glob"
)

const (
	maxCatalogReachabilityInstructions = 4096
	maxCatalogReachabilityStates       = 8192
	maxCatalogReachabilityTransitions  = 1 << 18
	// maxCatalogReachabilitySteps caps the NFA work one firstAllowedCatalogPath
	// call may spend: every live instruction it visits, plus every word of a
	// state set it scans to find them. The state and transition caps do not
	// bound that. A pattern spelled with hundreds of "*" segments keeps a number
	// of instructions live that grows with the pattern, so a single transition
	// costs as much as the whole instruction budget while the transition cap
	// still admits a multi-second call, and a policy of many short rules widens
	// the product state instead, which the transition cap does not price either.
	// This is the cap that is proportional to work actually done.
	//
	// Exhausting it returns indeterminate, the same conservative "could not
	// prove reachability, treat the endpoint as exposed" verdict the other caps
	// return, so a config that trips it is reported under its catalog spelling
	// instead of being silently passed. 1<<23 is 148x the 56,537 steps the
	// heaviest policy in configs/ spends on its most expensive catalog row,
	// which is also the ceiling across the whole test suite, so only a pattern
	// built to be expensive reaches it: it takes a few hundred "*" segments in
	// one path segment. That caps one call at around 30ms and a walk of both
	// sensitive-endpoint catalogs over such a config at under a second, against
	// the 14s the same config cost before this budget existed.
	maxCatalogReachabilitySteps = 1 << 23
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
	steps       int
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
// number of rules, and a long rule pattern makes each step of that product
// expensive on its own. Work per call is therefore capped four ways: program
// size, states, transitions, and the NFA work a search may spend
// (maxCatalogReachabilitySteps). The caps are not only a startup concern,
// because the admin API's POST /validate runs this walk again for every
// candidate config it is handed. Exhausting a cap returns indeterminate,
// which callers treat as exposed and fail closed rather than letting an
// unproved allow rule bypass an acknowledgment.
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
	}
	// filter.pathMatcherSegmentGlob needs no arm of its own: the segment walker
	// is defined as the anchored regex glob.ToRegexString already produces, and
	// the default expression above is exactly that. It used to re-root the
	// pattern ("/" + ToRegexString(TrimPrefix(pattern, "/"))) to mirror the
	// walker's leading-slash trim, which was a no-op for a rooted pattern and
	// modeled a widening for a rootless one; the walker no longer trims.
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

// reachabilityProduct lays every machine's NFA state set end to end in one word
// slice. A product state is then a single allocation and its map key is a
// single copy, instead of one allocation per machine plus a second pass to
// concatenate them, which the search pays on every transition it examines.
type reachabilityProduct struct {
	machines []catalogRuleMachine
	offsets  []int
	words    int
}

func newReachabilityProduct(machines []catalogRuleMachine) reachabilityProduct {
	offsets := make([]int, len(machines)+1)
	words := 0
	for i := range machines {
		offsets[i] = words
		words += (len(machines[i].program.Inst) + 63) / 64
	}
	offsets[len(machines)] = words
	return reachabilityProduct{machines: machines, offsets: offsets, words: words}
}

func (p reachabilityProduct) state(product []uint64, machine int) []uint64 {
	return product[p.offsets[machine]:p.offsets[machine+1]]
}

type reachabilityState struct {
	product []uint64
	// parent and step spell the witness as a linked list back to the start
	// state. Carrying the witness string on the state instead re-copies the
	// whole prefix for every state queued, which is quadratic in the witness
	// length and so in the pattern length that sets it.
	parent int
	step   rune
}

// catalogAllowWitness receives the positive catalog first, catalog exclusions
// and every rule earlier than the target allow next, and the target allow last.
// It finds a string accepted by the catalog and target but by none of the
// exclusions or earlier rules, which is precisely first-match reachability for
// that allow on the upstream route language.
func catalogAllowWitness(machines []catalogRuleMachine, budget *catalogReachabilityBudget) (string, catalogReachability) {
	product := newReachabilityProduct(machines)
	last := len(machines) - 1

	start := make([]uint64, product.words)
	for i := range machines {
		reachabilityAddClosure(machines[i].program, product.state(start, i), machines[i].program.Start, budget)
	}

	key := make([]byte, product.words*8)
	scratch := make([]uint64, product.words)
	working := &reachabilityCandidates{}
	reachabilityFillKey(key, start)

	queue := []reachabilityState{{product: start, parent: -1}}
	seen := map[string]struct{}{string(key): {}}
	for head := 0; head < len(queue); head++ {
		current := queue[head].product
		if catalogAllowAccepts(product, current) {
			return reachabilityWitness(queue, head), catalogReachable
		}

		candidates := reachabilityCandidateRunes(product, current, working, budget)
		if budget.steps > maxCatalogReachabilitySteps {
			return "", catalogReachabilityIndeterminate
		}
		for _, candidate := range candidates {
			budget.transitions++
			if budget.transitions > maxCatalogReachabilityTransitions {
				return "", catalogReachabilityIndeterminate
			}
			for i := range machines {
				reachabilityAdvance(machines[i].program, product.state(current, i), product.state(scratch, i), candidate, budget)
			}
			if budget.steps > maxCatalogReachabilitySteps {
				return "", catalogReachabilityIndeterminate
			}
			// A dead catalog can never come back, and neither can a dead
			// target: reachabilityAdvance maps the empty state set to itself
			// and catalogAllowAccepts demands both of them accept. Dropping
			// the target here is what keeps a long literal pattern from
			// walking the whole catalog language after the pattern itself has
			// already been ruled out one character in.
			if reachabilityEmpty(product.state(scratch, 0)) || reachabilityEmpty(product.state(scratch, last)) {
				continue
			}
			reachabilityFillKey(key, scratch)
			if _, ok := seen[string(key)]; ok {
				continue
			}
			budget.states++
			if budget.states > maxCatalogReachabilityStates {
				return "", catalogReachabilityIndeterminate
			}
			seen[string(key)] = struct{}{}
			queue = append(queue, reachabilityState{
				product: slices.Clone(scratch),
				parent:  head,
				step:    candidate,
			})
		}
	}

	return "", catalogUnreachable
}

// reachabilityWitness walks the parent links back to the start state and spells
// the runes that got there.
func reachabilityWitness(queue []reachabilityState, index int) string {
	steps := make([]rune, 0, index)
	for index > 0 {
		steps = append(steps, queue[index].step)
		index = queue[index].parent
	}
	slices.Reverse(steps)
	return string(steps)
}

func catalogAllowAccepts(product reachabilityProduct, states []uint64) bool {
	last := len(product.machines) - 1
	if !reachabilityAccepts(product.machines[0].program, product.state(states, 0)) ||
		!reachabilityAccepts(product.machines[last].program, product.state(states, last)) {
		return false
	}
	for i := 1; i < last; i++ {
		if reachabilityAccepts(product.machines[i].program, product.state(states, i)) {
			return false
		}
	}
	return true
}

// reachabilityAdvance overwrites next with the states current reaches on
// candidate. It walks the live set word by word rather than the whole
// instruction list, so the cost is the number of live instructions and not the
// program size — the difference between linear and constant work per
// transition once a long pattern has compiled to thousands of instructions.
func reachabilityAdvance(program *syntax.Prog, current, next []uint64, candidate rune, budget *catalogReachabilityBudget) {
	for i := range next {
		next[i] = 0
	}
	budget.steps += len(current)
	for word, live := range current {
		for live != 0 {
			pc := word*64 + bits.TrailingZeros64(live)
			live &= live - 1
			budget.steps++
			instruction := &program.Inst[pc]
			if !reachabilityInstructionMatches(instruction, candidate) {
				continue
			}
			reachabilityAddClosure(program, next, int(instruction.Out), budget)
		}
	}
}

func reachabilityAddClosure(program *syntax.Prog, state []uint64, start int, budget *catalogReachabilityBudget) {
	stack := []int{start}
	for len(stack) > 0 {
		last := len(stack) - 1
		pc := stack[last]
		stack = stack[:last]
		if pc < 0 || pc >= len(program.Inst) || reachabilityHas(state, pc) {
			continue
		}
		budget.steps++
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

// reachabilityPreferredRunes lead every candidate list so a witness spells the
// readable identifier a reader expects wherever the languages leave a choice.
var reachabilityPreferredRunes = []rune{'a', 'b', '0', '-', '_', '.', '/', '\n'}

// reachabilityCandidates is the working set reachabilityCandidateRunes builds.
// The search reuses one per call: the map and both slices are rebuilt for every
// state visited, and allocating them fresh each time costs more than the scan
// they exist for.
type reachabilityCandidates struct {
	members map[rune]struct{}
	ordered []rune
	rest    []rune
}

func (c *reachabilityCandidates) reset() {
	if c.members == nil {
		c.members = make(map[rune]struct{}, 64)
	} else {
		clear(c.members)
	}
	c.ordered = c.ordered[:0]
	c.rest = c.rest[:0]
	for _, candidate := range reachabilityPreferredRunes {
		c.members[candidate] = struct{}{}
	}
}

func reachabilityCandidateRunes(product reachabilityProduct, states []uint64, working *reachabilityCandidates, budget *catalogReachabilityBudget) []rune {
	working.reset()
	candidates := working.members
	budget.steps += product.words
	for i := range product.machines {
		program := product.machines[i].program
		for word, live := range product.state(states, i) {
			for live != 0 {
				pc := word*64 + bits.TrailingZeros64(live)
				live &= live - 1
				budget.steps++
				instruction := program.Inst[pc]
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
	}

	for _, candidate := range reachabilityPreferredRunes {
		if _, ok := candidates[candidate]; ok {
			working.ordered = append(working.ordered, candidate)
			delete(candidates, candidate)
		}
	}
	for candidate := range candidates {
		if candidate >= 0 && candidate <= unicode.MaxRune && (candidate < 0xD800 || candidate > 0xDFFF) {
			working.rest = append(working.rest, candidate)
		}
	}
	slices.Sort(working.rest)
	working.ordered = append(working.ordered, working.rest...)
	return working.ordered
}

func addReachabilityBoundaryRunes(candidates map[rune]struct{}, boundary rune) {
	for _, candidate := range []rune{boundary - 1, boundary, boundary + 1} {
		if candidate >= 0 && candidate <= unicode.MaxRune && (candidate < 0xD800 || candidate > 0xDFFF) {
			candidates[candidate] = struct{}{}
		}
	}
}

func reachabilityAccepts(program *syntax.Prog, state []uint64) bool {
	for word, live := range state {
		for live != 0 {
			pc := word*64 + bits.TrailingZeros64(live)
			live &= live - 1
			if program.Inst[pc].Op == syntax.InstMatch {
				return true
			}
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

// reachabilityFillKey writes the product state into a caller-owned buffer so
// the map key costs one copy and no allocation. Only a state that survives the
// seen check is ever turned into a string, which is bounded by
// maxCatalogReachabilityStates rather than by the transition count.
func reachabilityFillKey(key []byte, states []uint64) {
	for i, word := range states {
		binary.LittleEndian.PutUint64(key[i*8:], word)
	}
}

func reachabilityHas(state []uint64, pc int) bool {
	return state[pc/64]&(uint64(1)<<uint(pc%64)) != 0
}

func reachabilitySet(state []uint64, pc int) {
	state[pc/64] |= uint64(1) << uint(pc%64)
}
