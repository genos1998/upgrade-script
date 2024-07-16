package common

import (
	"os"
	"strings"
	"upgradationScript/logger"

	"github.com/OpsMx/ssd-jwt-auth/ssdjwtauth"
	"gopkg.in/yaml.v2"
)

type Configuration struct {
	ProdGraphQLAddr        string `json:"prodGraphQLAddr,omitempty" yaml:"prodGraphQLAddr,omitempty"`
	ExpGraphQLAddr         string `json:"expGraphQLAddr,omitempty" yaml:"expGraphQLAddr,omitempty"`
	ProdDgraphToken        string `json:"prodDgraphToken,omitempty" yaml:"prodDgraphToken,omitempty"`
	ExpDgraphToken         string `json:"expDgraphToken,omitempty" yaml:"expDgraphToken,omitempty"`
	UpgradeToVersion       string `json:"upgradeToVersion,omitempty" yaml:"upgradeToVersion,omitempty"`
	RemoteDgraphRestoreUrl string `json:"remoteDgraphRestoreUrl,omitempty" yaml:"remoteDgraphRestoreUrl,omitempty"`
}

var (
	Conf             *Configuration
	TokenVerifier    *ssdjwtauth.Verifier
	UpgradeToVersion SchemaOrder
)

func LoadConfigurationFile(confPath string) {

	buf, err := os.ReadFile(confPath)
	if err != nil {
		logger.Logger.Sugar().Fatalw("os.ReadFile", "error", err.Error())
	}

	if err := yaml.Unmarshal(buf, &Conf); err != nil {
		logger.Logger.Sugar().Fatalw("yaml.Unmarshal", "error", err.Error())
	}

	if strings.TrimSpace(Conf.ProdGraphQLAddr) == "" {
		logger.Logger.Sugar().Fatalw("prodGraphQLAddr is empty Please provide")
	}

	if strings.TrimSpace(Conf.ProdDgraphToken) == "" {
		logger.Logger.Sugar().Fatalw("prodDgraphToken is empty Please provide")
	}

	TokenVerifier, err = ssdjwtauth.NewVerifier(map[string][]byte{}, nil)
	if err != nil {
		logger.Logger.Sugar().Fatalf("ssdjwtauth.NewVerifier: err : %s", err.Error())
	}

	if strings.TrimSpace(Conf.UpgradeToVersion) == "" {
		logger.Logger.Sugar().Fatalw("upgradeToVersion is empty Please provide")
	}

	var ok bool
	UpgradeToVersion, ok = schemaOrderMap[Conf.UpgradeToVersion]
	if !ok {
		logger.Logger.Sugar().Fatalw("unrecognized schema version provided. Please provide in format MonthYYYY eg November2024")
	}

}
