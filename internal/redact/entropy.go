package redact

import (
	"math"
	"strings"
)

// minLen is the shortest value the entropy heuristic will inspect.
const minLen = 16

// minBits is the Shannon-entropy floor (bits per character) for a
// value to count as credential material. Timestamps and host:port
// strings sit well below it; random base64/hex tokens sit above.
const minBits = 4.0

// Shannon returns the entropy of s in bits per character.
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// IsHighEntropy reports whether v looks like a generated credential:
// long enough, no whitespace, high Shannon entropy. Timestamps,
// URLs and host:port values stay below the bar so correlation data
// survives.
func IsHighEntropy(v string) bool {
	if len(v) < minLen || strings.ContainsAny(v, " \t\n\r") {
		return false
	}
	return Shannon(v) >= minBits
}
