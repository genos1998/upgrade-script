package april2024june2024

import (
	"fmt"

	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToJune2024(prodGraphUrl, prodToken, expDgraphUrl, restoreServiceUrl string, prodDgraphClient, expDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToJune2024------------------")

	if err := performDeDeplicationTransition(prodDgraphClient, expDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToJune2024: %s", err.Error())
	}

	if err := graphqlfunc.BackupAndRestoreDgraph(expDgraphUrl, restoreServiceUrl); err != nil {
		return fmt.Errorf("UpgradeToJune2024: BackupAndRestoreDgraph: %s", err.Error())
	}

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.June2024Schema)); err != nil {
		return fmt.Errorf("UpgradeToJune2024: UpdateSchema: %s", err.Error())
	}

	if err := populateAppLevelTools(prodDgraphClient); err != nil {
		return fmt.Errorf("UpgradeToJune2024: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToJune2024------------------")

	return nil
}
