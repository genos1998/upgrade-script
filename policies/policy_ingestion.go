package policyingenstionscript

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

type PolicyDefinitionScript struct {
	PolicyId        string      `json:"policyId,omitempty" yaml:"policyId,omitempty"`
	PolicyName      string      `json:"policyName,omitempty" yaml:"policyName,omitempty"`
	Category        string      `json:"category,omitempty" yaml:"category,omitempty"`
	Stage           string      `json:"stage,omitempty" yaml:"stage,omitempty"`
	Description     string      `json:"description,omitempty" yaml:"description,omitempty"`
	ScheduledPolicy bool        `json:"scheduled_policy,omitempty" yaml:"scheduledPolicy,omitempty"`
	ScriptId        string      `json:"scriptId,omitempty" yaml:"scriptId,omitempty"`
	Variables       string      `json:"variables,omitempty" yaml:"variables,omitempty"`
	ConditionName   string      `json:"conditionName,omitempty" yaml:"conditionName,omitempty"`
	Suggestion      interface{} `json:"suggestion,omitempty" yaml:"suggestion,omitempty"`
}

type PolicyEnforcementScript struct {
	PolicyId       string   `json:"policyId,omitempty" yaml:"policyId,omitempty"`
	Severity       string   `json:"severity,omitempty" yaml:"severity,omitempty"`
	Action         string   `json:"action,omitempty" yaml:"action,omitempty"`
	ConditionValue string   `json:"conditionValue,omitempty" yaml:"conditionValue,omitempty"`
	Status         bool     `json:"status,omitempty" yaml:"status,omitempty"`
	Tags           []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	DatasourceTool string   `json:"datasourceTool,omitempty" yaml:"datasourceTool,omitempty"`
}

type TagScript struct {
	Id             string `json:"id,omitempty" yaml:"id,omitempty"`
	TagName        string `json:"tagName,omitempty" yaml:"tagName,omitempty"`
	TagValue       string `json:"tagValue,omitempty" yaml:"tagValue,omitempty"`
	TagDescription string `json:"tagDescription,omitempty" yaml:"tagDescription,omitempty"`
	CreatedBy      string `json:"createdBy,omitempty" yaml:"createdBy,omitempty"`
}

var tagIdInScriptMapIdInDB = make(map[string]string)
var policyDefInScriptMapIdInDB = make(map[string]string)

func UpgradePolicyAndTagData(graphqlClient graphql.Client, orgId string) error {

	if err := ingestTags(graphqlClient); err != nil {
		return fmt.Errorf("upgradePolicyAndTagData: %s", err.Error())
	}

	if err := ingestPolicyDef(graphqlClient, orgId); err != nil {
		return fmt.Errorf("upgradePolicyAndTagData: %s", err.Error())
	}

	if err := ingestPolicyEnforcement(graphqlClient, orgId); err != nil {
		return fmt.Errorf("upgradePolicyAndTagData: %s", err.Error())
	}
	return nil

}

func ingestTags(graphqlClient graphql.Client) error {

	logger.Sl.Debugf("---------------------Starting Tags ingestion---------------------")

	for i, tag := range tagPolicy {

		var allTagInputs []*AddTagInput
		var tagScript TagScript
		if err := json.Unmarshal([]byte(tag), &tagScript); err != nil {
			return fmt.Errorf("ingestTags: json.Unmarshal: iteration: %d err: %s", i, err.Error())
		}

		existingTag, err := checkIfTagExists(context.Background(), graphqlClient, tagScript.TagName, tagScript.TagValue, tagScript.CreatedBy)
		if err != nil {
			return fmt.Errorf("ingestTags: checkIfTagExists: iteration: %d err: %s", i, err.Error())
		}

		if existingTag.QueryTag != nil && len(existingTag.QueryTag) > 0 {

			tagIdInScriptMapIdInDB[tagScript.Id] = existingTag.QueryTag[0].Id

			logger.Sl.Debugf("ingestTags: tag already exists skipping ingestion of tag iteration: %d", i)
			continue
		}

		lastTag, err := getLastTagId(context.Background(), graphqlClient)
		if err != nil {
			return fmt.Errorf("ingestTags: getLastTagId: iteration: %d err: %s", i, err.Error())
		}

		tagIdInt := *lastTag.AggregateTag.Count + 1

		currTime := time.Now().UTC()
		newTagInput := AddTagInput{
			Id:             fmt.Sprintf("%d", tagIdInt),
			TagName:        tagScript.TagName,
			TagValue:       tagScript.TagValue,
			TagDescription: tagScript.TagDescription,
			CreatedBy:      tagScript.CreatedBy,
			CreatedAt:      &currTime,
			UpdatedAt:      &currTime,
		}

		logger.Sl.Debugf("ingestTags: will add new tag %s", newTagInput.TagValue)

		tagIdInScriptMapIdInDB[tagScript.Id] = newTagInput.Id

		allTagInputs = append(allTagInputs, &newTagInput)

		if _, err := addTag(context.Background(), graphqlClient, allTagInputs); err != nil {
			return fmt.Errorf("ingestTags: addTags: error: %s", err.Error())
		}

	}

	logger.Sl.Debugf("-------------------Completed Tags ingestion----------------------")

	return nil
}

func ingestPolicyDef(graphqlClient graphql.Client, orgId string) error {

	logger.Sl.Debugf("---------------Started PolicyDef ingestion-------------------")

	for i, policyDef := range policyDefinition {

		var addPoliciesDef []*AddPolicyDefinitionInput

		var policyDefScript PolicyDefinitionScript
		if err := json.Unmarshal([]byte(policyDef), &policyDefScript); err != nil {
			return fmt.Errorf("ingestPolicyDef: json.Unmarshal: iteration: %v err: %s", i, err.Error())
		}

		scriptID, _ := strconv.Atoi(policyDefScript.ScriptId)

		checkIfPolicyNameExistsResp, err := checkIfPolicyNameExists(context.Background(), graphqlClient, policyDefScript.PolicyName, orgId)
		if err != nil {
			return fmt.Errorf("ingestPolicyDef: checkIfPolicyNameExists: iteration: %v err: %s", i, err.Error())
		}

		now := time.Now().UTC()

		// update policy flow
		if len(checkIfPolicyNameExistsResp.QueryPolicyDefinition) != 0 {
			policyDefInScriptMapIdInDB[policyDefScript.PolicyId] = checkIfPolicyNameExistsResp.QueryPolicyDefinition[0].Id
			logger.Sl.Debugf("ingestPolicyDef: policyDef PolicyName already exists checking if exact policy is available iteration: %v", i)

			exactExists, err := checkIfExactPolicyDefinitionExists(context.Background(), graphqlClient, policyDefScript.PolicyName, policyDefScript.Category, policyDefScript.Stage, policyDefScript.Description, &policyDefScript.ScheduledPolicy, scriptMap[scriptID], policyDefScript.Variables, policyDefScript.ConditionName, "", orgId)
			if err != nil {
				return fmt.Errorf("ingestPolicyDef: checkIfExactPolicyDefinitionExists: iteration: %v err: %s", i, err.Error())
			}

			if len(exactExists.QueryPolicyDefinition) != 0 {
				logger.Sl.Debugf("ingestPolicyDef: exact policyDef already exists skipping iteration: %v", i)
				continue
			}

			if _, err := updatePolicyDefinition(context.Background(), graphqlClient, checkIfPolicyNameExistsResp.QueryPolicyDefinition[0].Id, policyDefScript.Category, policyDefScript.Stage, policyDefScript.Description, &policyDefScript.ScheduledPolicy, scriptMap[scriptID], policyDefScript.Variables, policyDefScript.ConditionName, "", &now); err != nil {
				return fmt.Errorf("ingestPolicyDef: updatePolicyDefinition: iteration: %v err: %s", i, err.Error())
			}

			logger.Sl.Debugf("ingestPolicyDef: policyDef updated iteration: %v", i)
			continue
		}

		getLastPolicyIdResp, err := getLastPolicyId(context.Background(), graphqlClient, orgId)
		if err != nil {
			return fmt.Errorf("ingestPolicyDef: getLastPolicyId: iteration: %v err: %s", i, err.Error())
		}

		policyDefIdInt := *getLastPolicyIdResp.QueryOrganization[0].PoliciesAggregate.Count + 1

		policy := AddPolicyDefinitionInput{
			Id: fmt.Sprintf("%v", policyDefIdInt),
			OwnerOrg: &OrganizationRef{
				Id: orgId,
			},
			CreatedAt:       &now,
			UpdatedAt:       &now,
			PolicyName:      policyDefScript.PolicyName,
			Category:        policyDefScript.Category,
			Stage:           policyDefScript.Stage,
			Description:     policyDefScript.Description,
			Script:          scriptMap[scriptID],
			ScheduledPolicy: &policyDefScript.ScheduledPolicy,
			Variables:       policyDefScript.Variables,
			ConditionName:   policyDefScript.ConditionName,
		}

		policyDefInScriptMapIdInDB[policyDefScript.PolicyId] = policy.Id

		logger.Sl.Debugf("ingestPolicyDef: will add policyDef iteration: %d", i)

		addPoliciesDef = append(addPoliciesDef, &policy)

		if _, err := addPolicyDefinition(context.TODO(), graphqlClient, addPoliciesDef); err != nil {
			return fmt.Errorf("ingestPolicyDef: addPolicyDefinition: err: %s", err.Error())
		}
	}

	logger.Sl.Debug("----------------Completed PolicyDef ingestion-----------------------")

	return nil
}

func ingestPolicyEnforcement(graphqlClient graphql.Client, orgId string) error {

	logger.Sl.Debugf("---------------------Starting Policy Enf ingestion---------------------")

	var allPolicyEnf []*AddPolicyEnforcementInput

	for i, enf := range policyEnforcement {

		var policyEnfScript PolicyEnforcementScript
		if err := json.Unmarshal([]byte(enf), &policyEnfScript); err != nil {
			return fmt.Errorf("ingestPolicyEnforcement: json.Unmarshal: iteration: %v err: %s", i, err.Error())
		}

		checkIfPolicyEnforcementExistsResp, err := checkIfPolicyEnforcementExists(context.Background(), graphqlClient, policyEnfScript.DatasourceTool, policyDefInScriptMapIdInDB[policyEnfScript.PolicyId])
		if err != nil {
			return fmt.Errorf("ingestPolicyEnforcement: checkIfPolicyEnforcementExists: iteration: %v err: %s", i, err.Error())
		}

		now := time.Now().UTC()

		if len(checkIfPolicyEnforcementExistsResp.QueryPolicyEnforcement) != 0 {

			for _, eachPolicyEnf := range checkIfPolicyEnforcementExistsResp.QueryPolicyEnforcement {

				if eachPolicyEnf.ConditionValue != policyEnfScript.ConditionValue {
					if _, err := updatePolicyEnforcement(context.Background(), graphqlClient, policyEnfScript.ConditionValue, eachPolicyEnf.Id, &now); err != nil {
						return fmt.Errorf("ingestPolicyEnforcement: updatePolicyEnforcement: policyEnfId: %s iteration: %v err: %s", *eachPolicyEnf.Id, i, err.Error())
					}
				}

				for _, eachTagScript := range policyEnfScript.Tags {

					found := false
					checkForTagId := tagIdInScriptMapIdInDB[eachTagScript]

					for _, eachTagDb := range eachPolicyEnf.Tags {

						if found {
							continue
						}

						if eachTagDb.Id == checkForTagId {
							found = true
						}
					}

					if found {
						continue
					}

					if _, err := assignTagsToPolicy(context.Background(), graphqlClient, eachPolicyEnf.Id, &TagRef{Id: checkForTagId}, &now); err != nil {
						return fmt.Errorf("ingestPolicyEnforcement: assignTagsToPolicy: policyEnfId: %s iteration: %v err: %s", *eachPolicyEnf.Id, i, err.Error())
					}

				}

			}

			continue

		}

		policyEnf := AddPolicyEnforcementInput{
			Policy: &PolicyDefinitionRef{
				Id: policyDefInScriptMapIdInDB[policyEnfScript.PolicyId],
			},
			EnforcedOrg: &OrganizationRef{
				Id: orgId,
			},
			Status:         &policyEnfScript.Status,
			Severity:       MapSeverity(policyEnfScript.Severity),
			Action:         policyEnfScript.Action,
			ConditionValue: policyEnfScript.ConditionValue,
			CreatedAt:      &now,
			UpdatedAt:      &now,
			DatasourceTool: policyEnfScript.DatasourceTool,
		}

		var tags []*TagRef
		for _, tagId := range policyEnfScript.Tags {
			tags = append(tags, &TagRef{
				Id: tagIdInScriptMapIdInDB[tagId],
			})
		}

		policyEnf.Tags = tags

		allPolicyEnf = append(allPolicyEnf, &policyEnf)
	}

	if allPolicyEnf != nil {
		if _, err := addPolicyEnforcement(context.TODO(), graphqlClient, allPolicyEnf); err != nil {
			return fmt.Errorf("ingestPolicyEnforcement: addPolicyEnforcement: err: %s", err.Error())
		}
	}

	logger.Sl.Debugf("---------------------Completed Policy Enf ingestion---------------------")

	return nil
}

func MapSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	case "none":
		return SeverityNone
	default:
		return SeverityUnknown
	}
}
