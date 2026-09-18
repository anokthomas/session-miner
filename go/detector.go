// Package detector ports session-miner's hot path to Go (stdlib only).
// Same rules as miner.py: normalize volatile values, fingerprint per project,
// flag a retry loop when one normalized bash command repeats >=3 in 30 turns.
package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	reUUID    = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reHex     = regexp.MustCompile(`(?i)\b[0-9a-f]{7,64}\b`)
	reNum     = regexp.MustCompile(`\b\d+(\.\d+)?\b`)
	reAbsPath = regexp.MustCompile(`(/(Users|home|tmp|var|private|opt|usr)[^\s'"]*|~[^\s'"]*)`)
	rePort    = regexp.MustCompile(`:\d{2,5}\b`)
	reWS      = regexp.MustCompile(`\s+`)
)

// NormalizeCommand strips volatile tokens so the same failure mode matches
// across sessions without comparing full transcript text.
func NormalizeCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	cmd = reAbsPath.ReplaceAllString(cmd, "<PATH>")
	cmd = reUUID.ReplaceAllString(cmd, "<ID>")
	cmd = reHex.ReplaceAllString(cmd, "<HASH>")
	cmd = rePort.ReplaceAllString(cmd, ":<PORT>")
	cmd = reNum.ReplaceAllString(cmd, "<N>")
	cmd = reWS.ReplaceAllString(cmd, " ")
	return strings.ToLower(cmd)
}

// Fingerprint joins project + normalized behavior; stable across sessions.
func Fingerprint(project, normalized string) string {
	sum := sha256.Sum256([]byte(project + "|" + normalized))
	return "fp_" + hex.EncodeToString(sum[:])[:16]
}

// RetryLoop reports fingerprints seen >= threshold times in a 30-turn window.
// turns must already be ordered bash commands (empty strings skipped).
func RetryLoop(project string, turns []string, window, threshold int) []string {
	norm := make([]string, 0, len(turns))
	for _, t := range turns {
		if strings.TrimSpace(t) == "" {
			continue
		}
		norm = append(norm, NormalizeCommand(t))
	}
	seen := map[string]bool{}
	var out []string
	for s := 0; s < len(norm); s++ {
		counts := map[string]int{}
		for k := s; k < len(norm) && k < s+window; k++ {
			counts[norm[k]]++
			if counts[norm[k]] == threshold {
				fp := Fingerprint(project, "retry:"+norm[k])
				if !seen[fp] {
					seen[fp] = true
					out = append(out, fp)
				}
				break
			}
		}
	}
	return out
}
