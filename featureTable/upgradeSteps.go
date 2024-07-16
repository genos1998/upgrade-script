package featuretable

import (
	"context"
	"fmt"
	"time"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func FeatTableUpgradeSteps(graphqlClient graphql.Client, orgId string) error {

	logger.Sl.Debugf("---------------------Starting Feature Table ingestion---------------------")

	for i, eachFeatRec := range allRecords {

		logger.Sl.Debugf("Starting Feature Table ingestion for iteration: %d", i)

		exists, err := checkIfFeatureRecordExists(context.Background(), graphqlClient, eachFeatRec.Type, eachFeatRec.Scan)
		if err != nil {
			return fmt.Errorf("checkIfFeatureRecordExists: iter: %d error: %s", i, err.Error())
		}

		if len(exists.QueryFeatureMode) != 0 {
			logger.Sl.Debugf("Record for iter: %d already exists", i)
			continue
		}

		now := time.Now()
		if _, err := addNewRecordFeatureTable(context.Background(), graphqlClient, eachFeatRec.Id, orgId, eachFeatRec.Scan, eachFeatRec.Type, eachFeatRec.Category, &eachFeatRec.Enabled, &now); err != nil {
			return fmt.Errorf("addNewRecordFeatureTable: iter: %d error: %s", i, err.Error())
		}

		logger.Sl.Debugf("Added into Feature Table for iteration: %d", i)

	}

	logger.Sl.Debugf("---------------------Completed Feature Table ingestion---------------------")
	return nil

}
