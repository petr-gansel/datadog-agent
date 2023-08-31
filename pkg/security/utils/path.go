// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package utils

// PathPatternBuilderOpts PathPatternBuilder options
type PathPatternBuilderOpts struct {
	WildcardLimit      int // max number of wildcard in the pattern
	PrefixNodeRequired int // number of prefix nodes required
	SuffixNodeRequired int // number of suffix nodes required
	NodeSizeLimit      int // min size required to substitute with a wildcard
}

// PathPatternBuilder pattern builder for files
func PathPatternBuilder(pattern string, path string, opts PathPatternBuilderOpts) (bool, string) {
	if len(pattern) > len(path) {
		return false, ""
	}

	var (
		inPattern     bool
		wildcardCount = 0
		result        = make([]byte, len(pattern))
		size          = 0
		slash         bool
		i             = 0
		j             = 0
		prefixNodes   = 0
		suffixNodes   = 0
		nodeSize      = 0
	)

	for i < len(pattern) && j < len(path) {
		if pattern[i] == '*' {
			wildcardCount++

			// skip the remaining char of path until the next node
			for j < len(path) && path[j] != '/' {
				nodeSize++
				j++
			}

			if nodeSize > 0 && nodeSize < opts.NodeSizeLimit {
				return false, ""
			}

			result[size] = '*'
			size++

			i++
			continue
		}

		slash = pattern[i] == '/' || path[j] == '/'
		if slash {
			// the previous node wasn't a wildcard, so count it as either a plain prefix or suffix
			if i > 0 && !inPattern {
				if wildcardCount == 0 {
					prefixNodes++
				} else {
					suffixNodes++
				}
			} else if inPattern {
				if nodeSize < opts.NodeSizeLimit {
					return false, ""
				}
			}

			inPattern = false
		}

		if pattern[i] != path[j] {
			if slash {
				// slash should be at the same place
				return false, ""
			}

			if !inPattern {
				wildcardCount++
				if wildcardCount > opts.WildcardLimit {
					return false, ""
				}
				inPattern = true
				suffixNodes = 0

				result[size] = '*'
				size++
			}
			nodeSize++
		} else if !inPattern {
			result[size] = pattern[i]
			size++
		}

		i++
		j++
	}

	if !inPattern {
		suffixNodes++
	}

	if i == len(result) && j == len(path) && (wildcardCount == 0 || ((opts.PrefixNodeRequired == 0 || opts.PrefixNodeRequired <= prefixNodes) && (opts.SuffixNodeRequired == 0 || opts.SuffixNodeRequired <= suffixNodes))) {
		return true, string(result[0:size])
	}

	return false, ""
}
