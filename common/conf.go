package common

import (
	"fmt"
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
	UpgradeFromVersion     string `json:"upgradeFromVersion,omitempty" yaml:"upgradeFromVersion,omitempty"`
	RemoteDgraphRestoreUrl string `json:"remoteDgraphRestoreUrl,omitempty" yaml:"remoteDgraphRestoreUrl,omitempty"`
}

const (
	prodTokenPath = "/app/secrets/prod-token/token"
	expTokenPath  = "/app/secrets/exp-token/token"
)

var (
	Conf               *Configuration
	TokenVerifier      *ssdjwtauth.Verifier
	UpgradeToVersion   SchemaOrder
	UpgradeFromVersion SchemaOrder
)

func readFilePath(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error while reading file %s err:  %s", path, err.Error())
	}
	return key, nil
}

func LoadConfigurationFile(confPath string) {

	buf, err := readFilePath(confPath)
	if err != nil {
		logger.Logger.Sugar().Fatalw("readFilePath", "error", err.Error())
	}

	if err := yaml.Unmarshal(buf, &Conf); err != nil {
		logger.Logger.Sugar().Fatalw("yaml.Unmarshal", "error", err.Error())
	}

	if strings.TrimSpace(Conf.ProdGraphQLAddr) == "" {
		logger.Logger.Sugar().Fatalw("prodGraphQLAddr is empty Please provide")
	}

	prodTokenBytes, err := readFilePath(prodTokenPath)
	if err != nil {
		logger.Logger.Sugar().Fatalw("readFilePath: prodTokenPath: err: %s", err.Error())
	}

	if prodTokenBytes == nil {
		logger.Logger.Sugar().Fatalw("readFilePath: prodTokenPath: err: empty no token")
	}

	Conf.ProdDgraphToken = string(prodTokenBytes)

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
		logger.Logger.Sugar().Fatalw("unrecognized schema upgradeTo version provided. Please provide in format MonthYYYY eg November2024")
	}

	if Conf.UpgradeFromVersion != "" {
		UpgradeFromVersion, ok = schemaOrderMap[Conf.UpgradeFromVersion]
		if !ok {
			logger.Logger.Sugar().Fatalw("unrecognized schema upgradeFrom version provided. Please provide in format MonthYYYY eg November2024")
		}
	}

}
