package june2024june2024v2

import (
	"fmt"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
	"upgradationScript/schemas"

	"github.com/Khan/genqlient/graphql"
)

func UpgradeToJune2024V2(prodGraphUrl, prodToken string, prodDgraphClient graphql.Client) error {

	logger.Logger.Info("--------------Starting UpgradeToJune2024V2------------------")

	if err := graphqlfunc.UpdateSchema(prodGraphUrl, prodToken, []byte(schemas.June2024Version2)); err != nil {
		return fmt.Errorf("UpgradeToJune2024: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("--------------Completed UpgradeToJune2024V2------------------")

	return nil
}
