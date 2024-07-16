package april2024june2024

func AppendIfNotPresent(slice []string, str string) []string {

	if str == "" || str == "[]" {
		return slice
	}

	for _, s := range slice {
		if s == str {
			return slice // String already present, return original slice
		}
	}
	return append(slice, str) // String not present, append it to the slice
}
