package nginx

import (
	"regexp"
	"strconv"
	"strings"
)

// VarRef is one statically-proven variable definition that backed a
// target substitution: the name, the literal value it was assigned,
// and the defining file:line so evidence can cite its source.
type VarRef struct {
	Name  string // "$backend"
	Value string // literal value the config proved
	File  string // defining file
	Line  int    // defining directive line
	From  string // "set" or "map"
}

// Provenance renders the defining file:line of every substituted
// variable, in order, comma-separated.
func Provenance(refs []VarRef) string {
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		parts = append(parts, r.File+":"+strconv.Itoa(r.Line))
	}
	return strings.Join(parts, ", ")
}

// RenderedVars renders "$name=value" for every substituted variable.
func RenderedVars(refs []VarRef) string {
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		parts = append(parts, r.Name+"="+r.Value)
	}
	return strings.Join(parts, ", ")
}

// varPattern matches $name and ${name} references.
var varPattern = regexp.MustCompile(`\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))`)

// varNameOf strips the sigil and optional braces from one match.
func varNameOf(match string) string {
	inner := strings.TrimPrefix(match, "$")
	inner = strings.TrimPrefix(inner, "{")
	return "$" + strings.TrimSuffix(inner, "}")
}

// varDef is one assignment of a runtime variable found in the config.
// A non-static definition (value computed from other variables, a map
// with differing results, an include whose results were not read)
// still registers so it shadows any outer static definition: nginx
// would use the innermost assignment at runtime.
type varDef struct {
	name   string
	value  string
	static bool
	file   string
	line   int
	depth  int    // scope depth: http < server < location
	owner  string // route owner key for location-scoped sets, "" otherwise
	from   string // "set" or "map"
}

// varIndex collects every assignment seen while walking the tree.
type varIndex struct {
	defs map[string][]varDef
}

func newVarIndex() *varIndex { return &varIndex{defs: map[string][]varDef{}} }

func (vi *varIndex) add(d varDef) { vi.defs[d.name] = append(vi.defs[d.name], d) }

// lookup returns the value of name as the configuration proves it for
// the given route: the innermost scope wins, and the innermost scope
// must agree on exactly one literal value. Anything dynamic,
// ambiguous or unknown reports not found — resolution refuses to
// guess.
func (vi *varIndex) lookup(name, owner string) (varDef, bool) {
	var candidates []varDef
	best := -1
	for _, d := range vi.defs[name] {
		if d.owner != "" && d.owner != owner {
			continue // defined for a different route's scope
		}
		if d.depth > best {
			best = d.depth
			candidates = candidates[:0]
		}
		if d.depth == best {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 {
		return varDef{}, false
	}
	got := candidates[0]
	if !got.static {
		return varDef{}, false // innermost value is computed at runtime
	}
	for _, d := range candidates[1:] {
		if !d.static || d.value != got.value {
			return varDef{}, false // two different innermost values
		}
	}
	return got, true
}

// routeOwner is the stable identity a location-scoped definition is
// attached to. It deliberately excludes listen/server_name, which
// are only filled in after the location block has been walked.
func routeOwner(r *Route) string { return r.File + "\x00" + r.Location }

// mapAcc accumulates one map block's entries while its block is being
// walked.
type mapAcc struct {
	dest       string
	file       string
	line       int
	results    []string
	hasDefault bool
	poisoned   bool
}

// staticValue reports the single literal the map always produces.
// The map must have been read completely (no include), must declare a
// default (otherwise unmatched inputs yield an empty runtime value)
// and every entry must agree on one literal that references no
// other variable.
func (ma *mapAcc) staticValue() (string, bool) {
	if ma.poisoned || !ma.hasDefault || len(ma.results) == 0 {
		return "", false
	}
	v := trimQuotes(ma.results[0])
	for _, r := range ma.results[1:] {
		if trimQuotes(r) != v {
			return "", false // differing results: the input decides
		}
	}
	if strings.Contains(v, "$") {
		return "", false
	}
	return v, true
}

// definition turns the collected map into a variable definition. A
// map that is not statically resolvable still registers so it
// shadows any outer static assignment of the same name.
func (ma *mapAcc) definition(c ctx) varDef {
	d := varDef{
		name:  ma.dest,
		file:  ma.file,
		line:  ma.line,
		depth: c.scopeDepth(),
		from:  "map",
	}
	if v, ok := ma.staticValue(); ok {
		d.value, d.static = v, true
	}
	return d
}

// trimQuotes removes one layer of surrounding quotes the lexer may
// keep on a literal value.
func trimQuotes(s string) string { return strings.Trim(s, `"'`) }

// resolveRoutes substitutes statically-proven variables into targets
// that contain runtime references. A route is only rewritten when
// every referenced variable resolves to one literal from the config
// itself and the rewritten target classifies; otherwise the route
// keeps its unresolved target and the collector keeps reporting the
// blind spot. Target.Raw always stays the configured value so
// identity, fingerprint and evidence keep pointing at what was
// written.
func resolveRoutes(cfg *Config, vi *varIndex) {
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		if r.Target == nil || r.Target.Kind != TargetUnresolved {
			continue
		}
		raw := r.Target.Raw
		if !strings.Contains(raw, "$") {
			continue // unresolved for a non-variable reason
		}
		owner := routeOwner(r)
		var refs []VarRef
		seen := map[string]bool{}
		ok := true
		repl := varPattern.ReplaceAllStringFunc(raw, func(m string) string {
			name := varNameOf(m)
			d, found := vi.lookup(name, owner)
			if !found {
				ok = false
				return m
			}
			if !seen[name] {
				seen[name] = true
				refs = append(refs, VarRef{
					Name: name, Value: d.value,
					File: d.file, Line: d.line, From: d.from,
				})
			}
			return d.value
		})
		if !ok {
			continue // some variable stays unknown or dynamic
		}
		t := ParseTarget(repl)
		if t.Kind == TargetUnresolved {
			continue // still not classifiable: never guess
		}
		t.Raw = raw
		r.Target = &t
		r.Resolved = refs
	}
}
