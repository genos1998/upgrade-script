package april2024june2024

import (
	"context"
	"fmt"
	"upgradationScript/april2024june2024/june2024"

	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func populateAppLevelTools(prodDgraphClient graphql.Client) error {
	ctx := context.Background()

	logger.Logger.Debug("--------------Populating App Env Tools Data transition-----------------")

	appEnvs, err := june2024.AppEnvTools(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("populateAppLevelTools: could'nt query RunhistoriesData error: %s", err.Error())
	}

	for _, appEnv := range appEnvs.QueryApplicationEnvironment {
		logger.Logger.Debug("---------------------------------------------")
		logger.Sl.Debugf("App Env Tools to be populated for id %v", appEnv.Id)

		tools := []string{}

		for _, deployment := range appEnv.Deployments {
			logger.Sl.Debugf("Gathering Tools used in policy checks for deployment id %v", deployment.Id)
			for _, runHistory := range deployment.PolicyRunHistory {
				logger.Sl.Debugf("Tool used in policy run history id: %v is %v", runHistory.Id, runHistory.DatasourceTool)
				tools = AppendIfNotPresent(tools, runHistory.DatasourceTool)
			}
		}

		logger.Sl.Debugf("App Env Tools to be populated with tools %v for id %v", tools, appEnv.Id)

		if _, err := june2024.UpdateApplicationEnvironmentWithTools(ctx, prodDgraphClient, appEnv.Id, tools); err != nil {
			return fmt.Errorf("populateAppLevelTools: UpdateApplicationEnvironmentWithTools error: %s", err.Error())
		}

		logger.Sl.Debugf("added tools for AppEnv Id %v successfully", appEnv.Id)
		logger.Logger.Debug("---------------------------------------------")
	}

	logger.Logger.Debug("--------------Completed App Env Tools Data transition-----------------")

	return nil
}
