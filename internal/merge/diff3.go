// Package merge implements a line-based three-way merge (diff3) used by the
// config action's three_way_merge policy. It is in-tree rather than a third-party
// dependency: pure-Go BSD/MIT libraries provide two-way diffs only, so the
// three-way walk would be hand-written regardless, and avoiding a dependency
// keeps the trust surface small (a signed-package manager should not pull merge
// logic from an unaudited module). The walk anchors on base lines that are
// unchanged in BOTH live and incoming; this is conflict-safe (it never silently
// mis-merges, though it may flag a conflict a smarter aligner would resolve).
package merge

import "bytes"

// Result is the outcome of a three-way merge.
type Result struct {
	Merged    []byte
	Conflicts int
}

// Merge performs a line-based three-way merge of (base, live, incoming).
// The error return is reserved for future input-validation needs; it is
// currently always nil. Binary detection is the caller's responsibility.
func Merge(base, live, incoming []byte) (Result, error) {
	baseLines, _ := splitLines(base)
	liveLines, _ := splitLines(live)
	incLines, incTrailing := splitLines(incoming)

	merged, conflicts := walk(baseLines, liveLines, incLines)
	return Result{Merged: join(merged, incTrailing), Conflicts: conflicts}, nil
}

// splitLines splits b into lines without their trailing newline, and reports
// whether b ended with a newline. An empty input yields no lines.
func splitLines(b []byte) (lines []string, trailingNewline bool) {
	if len(b) == 0 {
		return nil, false
	}
	trailingNewline = b[len(b)-1] == '\n'
	s := string(b)
	if trailingNewline {
		s = s[:len(s)-1]
	}
	return splitOnNewline(s), trailingNewline
}

func splitOnNewline(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// join reconstructs a byte buffer from lines, appending a trailing newline only
// when trailingNewline is true (the merged result follows incoming's
// convention).
func join(lines []string, trailingNewline bool) []byte {
	if len(lines) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for i, ln := range lines {
		buf.WriteString(ln)
		if i < len(lines)-1 || trailingNewline {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// lcsMatch returns, for each index i in a, the index in b that a[i] is matched
// to under a longest common subsequence, or -1 if a[i] is not in the LCS.
func lcsMatch(a, b []string) []int {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == b[j]:
				dp[i][j] = dp[i+1][j+1] + 1
			case dp[i+1][j] >= dp[i][j+1]:
				dp[i][j] = dp[i+1][j]
			default:
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	match := make([]int, n)
	for i := range match {
		match[i] = -1
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			match[i] = j
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			i++
		default:
			j++
		}
	}
	return match
}

// walk produces the merged line sequence and a conflict count. It anchors on
// base lines unchanged in BOTH live and incoming, then resolves each inter-anchor
// region independently.
func walk(base, live, incoming []string) (out []string, conflicts int) {
	matchLive := lcsMatch(base, live)
	matchInc := lcsMatch(base, incoming)

	// Sentinel anchors bracket the whole file: a virtual base line at -1 maps to
	// live/incoming -1, and one at len(base) maps to len(live)/len(incoming).
	type anchor struct{ b, l, i int }
	anchors := []anchor{{-1, -1, -1}}
	for bi := 0; bi < len(base); bi++ {
		if matchLive[bi] >= 0 && matchInc[bi] >= 0 {
			anchors = append(anchors, anchor{bi, matchLive[bi], matchInc[bi]})
		}
	}
	anchors = append(anchors, anchor{len(base), len(live), len(incoming)})

	for k := 0; k+1 < len(anchors); k++ {
		lo, hi := anchors[k], anchors[k+1]
		baseReg := base[lo.b+1 : hi.b]
		liveReg := live[lo.l+1 : hi.l]
		incReg := incoming[lo.i+1 : hi.i]

		liveChanged := !slicesEqual(liveReg, baseReg)
		incChanged := !slicesEqual(incReg, baseReg)
		switch {
		case !liveChanged && !incChanged:
			out = append(out, baseReg...)
		case liveChanged && !incChanged:
			out = append(out, liveReg...)
		case !liveChanged && incChanged:
			out = append(out, incReg...)
		case slicesEqual(liveReg, incReg):
			out = append(out, liveReg...)
		default:
			out = appendConflict(out, liveReg, incReg)
			conflicts++
		}
		// Emit the anchor line itself (skip the trailing sentinel).
		if hi.b < len(base) {
			out = append(out, base[hi.b])
		}
	}
	return out, conflicts
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// appendConflict appends a two-marker conflict block wrapping the live region
// then the incoming region. No ||||||| BASE middle marker.
func appendConflict(out, live, incoming []string) []string {
	out = append(out, "<<<<<<< LIVE")
	out = append(out, live...)
	out = append(out, "=======")
	out = append(out, incoming...)
	out = append(out, ">>>>>>> INCOMING")
	return out
}
