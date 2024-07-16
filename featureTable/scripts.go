package featuretable

type FeatureTable struct {
	Id       string
	Enabled  bool
	Type     string
	Scan     string
	Category string
}

var allRecords = []FeatureTable{
	{
		Id:       "1",
		Enabled:  true,
		Type:     "trivy",
		Scan:     "licensescan",
		Category: "scanningtool",
	},
	{
		Id:       "2",
		Enabled:  true,
		Type:     "trivy",
		Scan:     "vulnerabilityscan",
		Category: "scanningtool",
	},
	{
		Id:       "3",
		Enabled:  true,
		Type:     "trivy",
		Scan:     "helmscan",
		Category: "scanningtool",
	},
	{
		Id:       "4",
		Enabled:  true,
		Type:     "trivy",
		Scan:     "secretscanforsource",
		Category: "scanningtool",
	},
	{
		Id:       "5",
		Enabled:  true,
		Type:     "trivy",
		Scan:     "secretscanforcontainers",
		Category: "scanningtool",
	},
	{
		Id:       "6",
		Enabled:  true,
		Type:     "openssf",
		Scan:     "compliancescan",
		Category: "scanningtool",
	},
	{
		Id:       "7",
		Enabled:  false,
		Type:     "semgrep",
		Scan:     "sastdastscan",
		Category: "scanningtool",
	},
	{
		Id:       "8",
		Enabled:  true,
		Type:     "kubescape",
		Scan:     "cisbenchmarkscan",
		Category: "scanningtool",
	},
	{
		Id:       "9",
		Enabled:  true,
		Type:     "kubescape",
		Scan:     "mitreandatt&ckscan",
		Category: "scanningtool",
	},
	{
		Id:       "10",
		Enabled:  true,
		Type:     "kubescape",
		Scan:     "nsa-cisascan",
		Category: "scanningtool",
	},
	{
		Id:       "11",
		Enabled:  true,
		Type:     "trivy",
		Scan:     "licensescanforsource",
		Category: "scanningtool",
	},
	{
		Id:       "12",
		Enabled:  false,
		Type:     "snyk",
		Scan:     "sastnykscan",
		Category: "scanningtool",
	},
}
