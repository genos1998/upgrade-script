package common

import (
	"upgradationScript/schemas"
)

type SchemaOrder int

const (
	UnIdentifiedVersion SchemaOrder = iota
	April2024Version
	June2024Version
)

var SchemasString = map[SchemaOrder]string{
	April2024Version: schemas.April2024Schema,
	June2024Version:  schemas.June2024Schema,
}

var schemaOrderMap = map[string]SchemaOrder{
	"April2024": April2024Version,
	"June2024":  June2024Version,
}

func (e SchemaOrder) NameOfSchema() string {
	for name, schemaOrder := range schemaOrderMap {
		if e == schemaOrder {
			return name
		}
	}

	return "UnidentifiedSchema"
}

func (e SchemaOrder) String() string {
	return SchemasString[e]
}

func (e SchemaOrder) Int() int {
	return int(e)
}

func getTheSchemaVersion(checkSchema string) SchemaOrder {

	for schemaEnum, schema := range SchemasString {

		if schema == checkSchema {
			return schemaEnum
		}
	}

	return UnIdentifiedVersion
}

func checkIfSchemaAtUpgradedVersion(schemaOrder SchemaOrder) bool {
	return schemaOrder.Int() == UpgradeToVersion.Int()
}

func checkIfSchemaUpgradeNotPossible(schemaOrder SchemaOrder) bool {
	return schemaOrder.Int() > UpgradeToVersion.Int()
}

func totalUpgradeSteps(schemaVersion SchemaOrder) int {
	return UpgradeToVersion.Int() - schemaVersion.Int()
}

func upgradeSchemaBasedOnStep(schemaVersion SchemaOrder, step int) SchemaOrder {
	step += 1
	return SchemaOrder(schemaVersion.Int() + step)
}
