package cron

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// Reference kinds a command head can classify into.
const (
	RefPath    = "path"    // absolute path: the script to run
	RefUnit    = "unit"    // systemctl target
	RefCommand = "command" // bare command name
	RefEnv     = "env"     // a variable decides the target
)

// Ref is one reference candidate found in a crontab command or a
// script body. Unresolved refs are reported, never guessed.
type Ref struct {
	Kind       string
	Value      string
	Line       int  // 1-based line inside the script; job line for commands
	Unresolved bool // an environment variable sits in the position
}

// CommandHead returns the first token of a command after stripping
// leading VAR=val assignments. The head is the position that decides
// what actually runs.
func CommandHead(cmd string) string {
	s := strings.TrimSpace(cmd)
	for s != "" {
		i := strings.IndexAny(s, " \t")
		tok := s
		if i >= 0 {
			tok, s = s[:i], strings.TrimSpace(s[i:])
		} else {
			s = ""
		}
		if isAssignment(tok) {
			continue
		}
		return tok
	}
	return ""
}

// isAssignment reports whether a token has the VAR=value shape.
func isAssignment(tok string) bool {
	i := strings.IndexByte(tok, '=')
	if i <= 0 {
		return false
	}
	for k, c := range tok[:i] {
		valid := c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(k > 0 && c >= '0' && c <= '9')
		if !valid {
			return false
		}
	}
	return true
}

// skipHeads are shell keywords and builtins: they never name a
// target, so they produce no reference.
var skipHeads = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"for": true, "while": true, "until": true, "do": true, "done": true,
	"case": true, "esac": true, "in": true, "function": true,
	"{": true, "}": true, "[": true, "!": true,
	"echo": true, "printf": true, "cd": true, "exit": true,
	"return": true, "local": true, "read": true, "shift": true,
	"break": true, "continue": true, "eval": true, "export": true,
	"true": true, "false": true, ":": true,
}

// systemctlVerbs are subcommands after "systemctl": the unit follows
// them (flags like --no-block are skipped).
var systemctlVerbs = map[string]bool{
	"start": true, "stop": true, "restart": true, "reload": true,
	"try-restart": true, "reload-or-restart": true, "enable": true,
	"disable": true, "mask": true, "unmask": true, "is-active": true,
	"is-enabled": true, "is-failed": true, "status": true, "show": true,
	"cat": true, "edit": true, "kill": true, "daemon-reload": true,
	"set-property": true, "preset": true,
}

// CommandRefs classifies every reference position of one command
// line. line is the 1-based line number to record.
func CommandRefs(cmd string, line int) []Ref {
	var refs []Ref
	for _, seg := range splitSegments(cmd) {
		head := CommandHead(seg)
		if head == "" || skipHeads[head] {
			continue
		}
		if r, ok := classifyHead(head, seg, line); ok {
			refs = append(refs, r)
		}
	}
	return refs
}

// ScriptRefs extracts reference candidates from a script body. It
// reports analyzable=false for content it refuses to interpret
// (binary, non-UTF-8 or base64-decoded payloads) — such content is
// reported, never decoded.
func ScriptRefs(content []byte) (refs []Ref, analyzable bool) {
	if !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
		return nil, false
	}
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(line, "base64 -d") || strings.Contains(line, "base64 --decode") {
			return nil, false
		}
		refs = append(refs, CommandRefs(line, i+1)...)
	}
	return refs, true
}

// classifyHead turns one command head into a reference. second is the
// whole segment, needed to find the systemctl unit.
func classifyHead(head, segment string, line int) (Ref, bool) {
	switch {
	case strings.HasPrefix(head, "$"):
		return Ref{Kind: RefEnv, Value: head, Line: line, Unresolved: true}, true
	case baseName(head) == "systemctl":
		// Checked before the path branch: /usr/bin/systemctl names a
		// unit, not a script to trace.
		unit := systemctlUnit(segment)
		if unit == "" {
			return Ref{}, false
		}
		if strings.HasPrefix(unit, "$") {
			return Ref{Kind: RefEnv, Value: unit, Line: line, Unresolved: true}, true
		}
		return Ref{Kind: RefUnit, Value: unit, Line: line}, true
	case strings.HasPrefix(head, "/"):
		return Ref{Kind: RefPath, Value: head, Line: line}, true
	case strings.IndexByte("<>&|(", head[0]) >= 0:
		return Ref{}, false // redirections and subshells, not targets
	default:
		return Ref{Kind: RefCommand, Value: head, Line: line}, true
	}
}

// systemctlUnit finds the unit argument of a systemctl segment.
func systemctlUnit(segment string) string {
	fields := strings.Fields(segment)
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "-") || systemctlVerbs[f] {
			continue
		}
		return f
	}
	return ""
}

// splitSegments cuts a line on shell command separators so each part
// gets its own head.
func splitSegments(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool {
		return r == ';' || r == '|' || r == '&' || r == '\n'
	})
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
