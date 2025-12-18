package util

import "strings"

// GatherName gathers the name. if enabled it will remove the dots at the end of the fdqn
// otherwise remove the resolvedzone from resolvedfqdn (leaving the distinct part) or fall back to fqdn without dot at the end if empty
func GatherName(fqdnNaming bool, resolvedFqdn, resolvedZone string) string {
	if fqdnNaming {
		return RemoveDotSuffixes(resolvedFqdn)
	}
	res := strings.TrimSuffix(resolvedFqdn, resolvedZone)
	res = strings.TrimRight(res, ".")
	if res != "" {
		return res
	}
	// Fallback: if result is empty, just return fqdn with removed dots at the end
	return RemoveDotSuffixes(resolvedFqdn)
}

// RemoveDotSuffixes removes all dots at the end of the given string
func RemoveDotSuffixes(in string) string {
	return strings.TrimRight(in, ".")
}
