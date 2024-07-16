package april2024june2024

import (
	"context"
	"fmt"
	"upgradationScript/april2024june2024/april2024"
	"upgradationScript/april2024june2024/june2024"

	"upgradationScript/logger"

	"github.com/Khan/genqlient/graphql"
)

func performDeDeplicationTransition(prodDgraphClient, expDgraphClient graphql.Client) error {

	ctx := context.Background()

	prodRunhistoriesData, err := april2024.QueryRunHistory(ctx, prodDgraphClient)
	if err != nil {
		return fmt.Errorf("performDeDeplicationTransition: could'nt query old prodRunhistoriesData to initiate de-duplication transition error: %s", err.Error())
	}

	logger.Sl.Debugf("--------------Commencing de-duplication transition iterations to complete %d -----------------", len(prodRunhistoriesData.QueryRunHistory))

	for iter, prodRunHistoryData := range prodRunhistoriesData.QueryRunHistory {
		logger.Logger.Debug("---------------------------------------------")
		logger.Sl.Debugf("De-Duplication Iteration %d to begin", iter)

		logger.Sl.Debugf("Check if security issue exists for alertTitle: %s alertMsg: %s suggestion: %s severity: %s errorMsg: %s action: %s", prodRunHistoryData.AlertTitle, prodRunHistoryData.AlertMessage, prodRunHistoryData.Suggestions, string(prodRunHistoryData.Severity), prodRunHistoryData.Error, prodRunHistoryData.Action)
		checkIfSecurityIssuePresent, err := june2024.QuerySecurityIssue(ctx, expDgraphClient, prodRunHistoryData.AlertTitle, prodRunHistoryData.AlertMessage, prodRunHistoryData.Suggestions, june2024.Severity(prodRunHistoryData.Severity), prodRunHistoryData.Error, prodRunHistoryData.Action)
		if err != nil {
			return fmt.Errorf("performDeDeplicationTransition: could'nt check if security issue data existed error: %s", err.Error())
		}

		if checkIfSecurityIssuePresent == nil || len(checkIfSecurityIssuePresent.QuerySecurityIssue) == 0 {
			logger.Logger.Debug("Security Issue of such metadata does not exist adding new")
			ip := june2024.AddSecurityIssueInput{
				AlertTitle:   prodRunHistoryData.AlertTitle,
				AlertMessage: prodRunHistoryData.AlertMessage,
				Suggestions:  prodRunHistoryData.Suggestions,
				Severity:     june2024.Severity(prodRunHistoryData.Severity),
				Action:       prodRunHistoryData.Action,
				Error:        prodRunHistoryData.Error,
				JiraUrl:      prodRunHistoryData.JiraUrl,
				Status:       "active",
				Reason:       "",
				CreatedAt:    prodRunHistoryData.CreatedAt,
				UpdatedAt:    prodRunHistoryData.CreatedAt,
			}

			addSecurityIssue, err := june2024.AddSecurityIssue(ctx, expDgraphClient, &ip)
			if err != nil {
				return fmt.Errorf("performDeDeplicationTransition: could not add security issue err: %s", err.Error())
			}

			checkIfSecurityIssuePresent.QuerySecurityIssue = append(checkIfSecurityIssuePresent.QuerySecurityIssue, &june2024.QuerySecurityIssueQuerySecurityIssue{})
			checkIfSecurityIssuePresent.QuerySecurityIssue[0].Id = addSecurityIssue.AddSecurityIssue.SecurityIssue[0].Id
			checkIfSecurityIssuePresent.QuerySecurityIssue[0].CreatedAt = prodRunHistoryData.CreatedAt
			checkIfSecurityIssuePresent.QuerySecurityIssue[0].UpdatedAt = prodRunHistoryData.CreatedAt

			logger.Logger.Debug("Security Issue of such metadata added")
		}

		logger.Sl.Debugf("updating run history id: %s by attaching it with security issue id: %s", *prodRunHistoryData.Id, *checkIfSecurityIssuePresent.QuerySecurityIssue[0].Id)
		if _, err := june2024.UpdateRunHistory(ctx, expDgraphClient, prodRunHistoryData.Id, checkIfSecurityIssuePresent.QuerySecurityIssue[0].Id); err != nil {
			return fmt.Errorf("performDeDeplicationTransition: UpdateRunHistory error: %s", err.Error())
		}
		logger.Sl.Debug("updated run history successfully")

		createdAt := checkIfSecurityIssuePresent.QuerySecurityIssue[0].CreatedAt
		updatedAt := checkIfSecurityIssuePresent.QuerySecurityIssue[0].UpdatedAt

		if checkIfSecurityIssuePresent.QuerySecurityIssue[0].CreatedAt.After(*prodRunHistoryData.CreatedAt) {
			createdAt = prodRunHistoryData.CreatedAt
		}

		if checkIfSecurityIssuePresent.QuerySecurityIssue[0].UpdatedAt.Before(*prodRunHistoryData.CreatedAt) {
			updatedAt = prodRunHistoryData.UpdatedAt
		}

		logger.Sl.Debug("updating security issue id: %s with createdAt: %s updatedAt: %s", *checkIfSecurityIssuePresent.QuerySecurityIssue[0].Id, createdAt.String(), updatedAt.String())
		if _, err := june2024.UpdateSecurityIssue(ctx, expDgraphClient, checkIfSecurityIssuePresent.QuerySecurityIssue[0].Id, createdAt, updatedAt); err != nil {
			return fmt.Errorf("performDeDeplicationTransition: UpdateSecurityIssue error: %s", err.Error())
		}
		logger.Sl.Debug("updated security issue successfully")

		logger.Sl.Debugf("De-Duplication Iteration %d completed", iter)
		logger.Logger.Debug("---------------------------------------------")
	}

	logger.Logger.Info("------------De-duplication upgrade complete-------------------------")

	return nil
}
