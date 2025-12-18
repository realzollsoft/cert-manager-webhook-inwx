package util

import "strings"

// GatherName gathers the name. if enabled it will return the fdqn
// otherwise remove the resolvedzone from resolvedfqdn (leaving the distinct part, without the dot) or fall back to fqdn
// inwx api either requires fqdn with dot at the end, or the short form without the dot
func GatherName(fqdnNaming bool, resolvedFqdn, resolvedZone string) string {
	if fqdnNaming {
		return resolvedFqdn
	}
	res := strings.TrimSuffix(resolvedFqdn, resolvedZone)
	res = strings.TrimRight(res, ".")
	if res != "" {
		return res
	}
	// Fallback: if result is empty, just return fqdn
	return resolvedFqdn
}

// RemoveDotSuffixes removes all dots at the end of the given string
func RemoveDotSuffixes(in string) string {
	return strings.TrimRight(in, ".")
}
