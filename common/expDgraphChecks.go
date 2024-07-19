package common

import (
	"fmt"
	"os"
	graphqlfunc "upgradationScript/graphqlFunc"
	"upgradationScript/logger"
)

func allChecksForExpDgraph(schema SchemaOrder) error {
	if Conf.ExpGraphQLAddr == "" {
		return fmt.Errorf("expGraphQLAddr is required")
	}

	expTokenBytes, err := readFilePath(expTokenPath)
	if err != nil {
		return fmt.Errorf("readFilePath: expTokenBytes: err: %s", err.Error())
	}

	if expTokenBytes == nil {
		return fmt.Errorf("readFilePath: expTokenBytes: err: empty no token")
	}

	Conf.ExpDgraphToken = string(expTokenBytes)

	if Conf.ExpDgraphToken == "" {
		return fmt.Errorf("expDgraphToken is required")
	}

	if Conf.RemoteDgraphRestoreUrl == "" {
		return fmt.Errorf("remoteDgraphRestoreUrl is required")
	}

	if _, found := os.LookupEnv("S3_ENDPOINT_URL"); !found {
		return fmt.Errorf("envar S3_ENDPOINT_URL is not set")
	}

	if _, found := os.LookupEnv("AWS_ACCESS_KEY_ID"); !found {
		return fmt.Errorf("envar AWS_ACCESS_KEY_ID is not set")
	}

	if _, found := os.LookupEnv("AWS_SECRET_ACCESS_KEY"); !found {
		return fmt.Errorf("envar AWS_SECRET_ACCESS_KEY is not set")
	}

	schemaPresent, err := graphqlfunc.RetrieveSchema(Conf.ExpGraphQLAddr)
	if err != nil {
		return fmt.Errorf("allChecksForExpDgraph: RetrieveSchema: %s", err.Error())
	}

	if getTheSchemaVersion(schemaPresent) == schema {
		return nil
	}

	logger.Logger.Info("-------Updating schema of exp dgraph--------------")

	if err := graphqlfunc.UpdateSchema(Conf.ExpGraphQLAddr, Conf.ExpDgraphToken, []byte(schema.String())); err != nil {
		return fmt.Errorf("allChecksForExpDgraph: UpdateSchema: %s", err.Error())
	}

	logger.Logger.Info("-------All checks passed of exp dgraph--------------")

	return nil
}
