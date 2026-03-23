package util

import "strings"

// GatherName gathers the name. if enabled it will return the fdqn
// otherwise remove the resolvedzone from resolvedfqdn (leaving the distinct part, without the dot) or fall back to fqdn
// inwx api either requires fqdn with dot at the end, or the short form without the dot
func GatherName(fqdnNaming bool, resolvedFqdn, resolvedZone string) string {
	if fqdnNaming {
		return resolvedFqdn
	}

	// Strip zone suffix and remove trailing dots
	res := strings.TrimSuffix(resolvedFqdn, resolvedZone)
	res = strings.TrimRight(res, ".")

	// Return original if stripping resulted in empty string
	if res == "" {
		return resolvedFqdn
	}

	return res
}

// TrimTrailingDots removes all trailing dots from a string
func TrimTrailingDots(in string) string {
	return strings.TrimRight(in, ".")
}
