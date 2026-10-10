package systemd

import (
	"fmt"
	"path"
	"strings"

	"archaeologist/internal/redact"
)

// Exec is one parsed ExecStart-style command.
type Exec struct {
	Prefixes string // stripped executor prefixes, e.g. "-", "@+"
	Path     string // raw path token (may still contain $VARS/%specifiers)
	Args     []string
	Line     int
	File     string
}

// execPrefixes are systemd's leading command modifiers.
const execPrefixes = "-@+!"

// ParseExec parses one ExecStart value into prefix, path and args.
// Quotes follow systemd syntax: "double" with backslash escapes and
// 'single' literal.
func ParseExec(value string, line int, file string) (Exec, error) {
	v := strings.TrimSpace(value)
	pre := ""
	for len(v) > 0 && strings.ContainsRune(execPrefixes, rune(v[0])) {
		pre += string(v[0])
		v = v[1:]
	}
	argv, err := SplitArgv(v)
	if err != nil {
		return Exec{}, err
	}
	if len(argv) == 0 {
		return Exec{}, fmt.Errorf("empty ExecStart")
	}
	return Exec{Prefixes: pre, Path: argv[0], Args: argv[1:], Line: line, File: file}, nil
}

// SplitArgv splits a systemd command string honoring single/double
// quotes and backslash escapes.
func SplitArgv(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inToken := false
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			inToken = true
			i += 2
		case c == '\'':
			inToken = true
			i++
			for i < len(s) && s[i] != '\'' {
				cur.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated single quote")
			}
			i++
		case c == '"':
			inToken = true
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					cur.WriteByte(s[i+1])
					i += 2
					continue
				}
				cur.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated double quote")
			}
			i++
		case c == ' ' || c == '\t':
			if inToken {
				out = append(out, cur.String())
				cur.Reset()
				inToken = false
			}
			i++
		default:
			cur.WriteByte(c)
			inToken = true
			i++
		}
	}
	if inToken {
		out = append(out, cur.String())
	}
	return out, nil
}

// Expand resolves $VARS from env and %specifiers from spec. It returns
// ok=false the moment something cannot be resolved, so callers record a
// blind spot instead of guessing.
func Expand(s string, env, spec map[string]string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch s[i] {
		case '$':
			if i+1 < len(s) && s[i+1] == '$' {
				b.WriteByte('$')
				i += 2
				continue
			}
			name, n := scanVar(s[i+1:])
			if n == 0 {
				return "", false
			}
			v, ok := env[name]
			if !ok {
				return "", false
			}
			b.WriteString(v)
			i += 1 + n
		case '%':
			if i+1 < len(s) && s[i+1] == '%' {
				b.WriteByte('%')
				i += 2
				continue
			}
			if i+1 >= len(s) {
				return "", false
			}
			v, ok := spec[string(s[i+1])]
			if !ok {
				return "", false
			}
			b.WriteString(v)
			i += 2
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String(), true
}

// scanVar reads a variable name after '$' — either NAME or {NAME}.
// It returns the name and bytes consumed after '$' (0 when invalid).
func scanVar(s string) (string, int) {
	if strings.HasPrefix(s, "{") {
		end := strings.IndexByte(s, '}')
		if end <= 1 {
			return "", 0
		}
		return s[1:end], end + 1
	}
	n := 0
	for n < len(s) {
		c := s[n]
		ok := c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(n > 0 && c >= '0' && c <= '9')
		if !ok {
			break
		}
		n++
	}
	return s[:n], n
}

// Specifiers builds the unit-derived specifier table (%n %N %i %I %p).
// Any other specifier stays unresolved → blind spot, never a guess.
func Specifiers(unitName string) map[string]string {
	base := unitName
	inst := ""
	if i := strings.IndexByte(unitName, '@'); i >= 0 {
		base = unitName[:i]
		rest := unitName[i+1:] // instance + type suffix, e.g. "7.service"
		if dot := strings.LastIndexByte(rest, '.'); dot >= 0 {
			inst = rest[:dot]
		} else {
			inst = rest
		}
	} else if dot := strings.LastIndexByte(base, '.'); dot >= 0 {
		base = base[:dot] // strip the type suffix
	}
	return map[string]string{
		"n": unitName,
		"N": unitName,
		"i": inst,
		"I": inst,
		"p": base,
	}
}

// EnvMap parses Environment directives ("FOO=bar", quoted pairs).
// Malformed tokens are skipped; a variable used later but missing will
// surface as an unresolved expansion.
func EnvMap(lines []Directive) map[string]string {
	env := map[string]string{}
	for _, d := range lines {
		toks, err := SplitArgv(d.Value)
		if err != nil {
			toks = strings.Fields(d.Value)
		}
		for _, t := range toks {
			eq := strings.IndexByte(t, '=')
			if eq <= 0 {
				continue
			}
			env[t[:eq]] = t[eq+1:]
		}
	}
	return env
}

// RedactEnvMap returns a copy of env with credential-bearing values
// replaced by the redaction mask, so expanded ExecStart arguments can
// be stored without leaking Environment= secrets. Path resolution
// keeps using the original map.
func RedactEnvMap(env map[string]string) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		if redact.IsSecretName(k) {
			out[k] = redact.Mask
			continue
		}
		out[k] = v
	}
	return out
}

// IsAbs reports an absolute filesystem path.
func IsAbs(p string) bool { return strings.HasPrefix(p, "/") }

// JoinPath resolves p against dir when p is relative.
func JoinPath(dir, p string) string {
	if IsAbs(p) || dir == "" {
		return p
	}
	return path.Clean(path.Join(dir, p))
}
