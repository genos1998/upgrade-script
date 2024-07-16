package graphqlfunc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/vektah/gqlparser/gqlerror"
)

type DgraphResponse struct {
	Data struct {
		GetGQLSchema struct {
			Schema string `json:"schema,omitempty" yaml:"schema,omitempty"`
		} `json:"getGQLSchema,omitempty" yaml:"getGQLSchema,omitempty"`
		Backup struct {
			TaskId string `json:"taskId,omitempty" yaml:"taskId,omitempty"`
		} `json:"backup,omitempty" yaml:"backup,omitempty"`
		Restore struct {
			TaskId string `json:"taskId,omitempty" yaml:"taskId,omitempty"`
		} `json:"restore,omitempty" yaml:"restore,omitempty"`
		Task struct {
			Status string `json:"status,omitempty" yaml:"status,omitempty"`
		} `json:"task,omitempty" yaml:"task,omitempty"`
	} `json:"data,omitempty" yaml:"data,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty" yaml:"extensions,omitempty"`
	Errors     gqlerror.List          `json:"errors,omitempty" yaml:"errors,omitempty"`
}

func DgraphAdminCall(dgraphUrl string, body []byte) (DgraphResponse, error) {
	dgraphUrl = fmt.Sprintf("%s/admin", dgraphUrl)
	httpClient := http.Client{}
	httpReq, err := http.NewRequest(
		http.MethodPost,
		dgraphUrl,
		bytes.NewReader(body),
	)
	if err != nil {
		return DgraphResponse{}, errors.New("DgraphAdminCall: http.NewRequest: error: " + err.Error())
	}

	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return DgraphResponse{}, errors.New("DgraphAdminCall: httpClient.Do: error: " + err.Error())
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		var respBody []byte
		respBody, err = io.ReadAll(httpResp.Body)
		if err != nil {
			respBody = []byte(fmt.Sprintf("<unreadable: %v>", err))
		}
		return DgraphResponse{}, fmt.Errorf("DgraphAdminCall: returned error %v: %s", httpResp.Status, respBody)
	}

	responseBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return DgraphResponse{}, errors.New("DgraphAdminCall: io.ReadAll: error: " + err.Error())
	}

	var resp DgraphResponse
	err = json.Unmarshal(responseBytes, &resp)
	if err != nil {
		return DgraphResponse{}, fmt.Errorf("DgraphAdminCall: json.Unmarshal error %v: %s", err, string(responseBytes))
	}

	if len(resp.Errors) > 0 {
		return DgraphResponse{}, fmt.Errorf("DgraphAdminCall: resp.Errors error %v", resp.Errors)
	}

	return resp, nil
}

func RetrieveSchema(dgraphUrl string) (string, error) {
	QueryGetGQLSchema_Operation := `
	query GetGQLSchema {
    	getGQLSchema {
        	schema
    	}
	}
	`

	req := &graphql.Request{
		OpName: "GetGQLSchema",
		Query:  QueryGetGQLSchema_Operation,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("RetrieveSchema: dgraphUrl: %s json.Marshal: error: %s", dgraphUrl, err.Error())
	}

	resp, err := DgraphAdminCall(dgraphUrl, body)
	if err != nil {
		return "", fmt.Errorf("RetrieveSchema: dgraphUrl: %s error: %s", dgraphUrl, err.Error())
	}

	return resp.Data.GetGQLSchema.Schema, nil
}

func setDrainingModeFalse(dgraphUrl string) error {
	drainingQuery := `mutation Draining {
		draining(enable: false) {
			response {
				message
			}
		}
	}`

	req := &graphql.Request{
		OpName: "Draining",
		Query:  drainingQuery,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("setDrainingModeFalse: json.Marshal: error: %s", err.Error())
	}

	if _, err := DgraphAdminCall(dgraphUrl, body); err != nil {
		return fmt.Errorf("setDrainingModeFalse dgraphUrl: %s error: %s", dgraphUrl, err.Error())
	}

	return nil
}

func generateDgraphBkp(dgraphUrl string) error {

	bkpQuery := `mutation Backup {
		backup(input: { destination: "/dgraph/bkp", forceFull: true }) {
			taskId
		}
	}`

	req := &graphql.Request{
		OpName: "Backup",
		Query:  bkpQuery,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("GenerateDgraphBkp: json.Marshal: error: %s", err.Error())
	}

	resp, err := DgraphAdminCall(dgraphUrl, body)
	if err != nil {
		return fmt.Errorf("GenerateDgraphBkp: backup init dgraphUrl: %s error: %s", dgraphUrl, err.Error())
	}

	taskId := resp.Data.Backup.TaskId

	taskQuery := `
	query Task {
		task(input: { id: "%s" }) {
			status
		}
	}
	`

	for {
		req := &graphql.Request{
			OpName: "Task",
			Query:  fmt.Sprintf(taskQuery, taskId),
		}
		body, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("GenerateDgraphBkp: task json.Marshal: error: %s", err.Error())
		}

		resp, err := DgraphAdminCall(dgraphUrl, body)
		if err != nil {
			return fmt.Errorf("GenerateDgraphBkp: backup task poll dgraphUrl: %s error: %s", dgraphUrl, err.Error())
		}

		if strings.EqualFold(resp.Data.Task.Status, "Success") {
			break
		}
		time.Sleep(1 * time.Minute)
	}

	return nil
}

type SchemaResult struct {
	Errors []SchemaResultError `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type SchemaResultError struct {
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}

func UpdateSchema(url, authToken string, schema []byte) error {

	if err := setDrainingModeFalse(url); err != nil {
		return err
	}

	ctx := context.Background()

	req, err := makeRequest(ctx, url+"/admin/schema", http.MethodPost, authToken, bytes.NewReader(schema))
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("submit returned status %d", resp.StatusCode)
	}

	r, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var schemaResult SchemaResult
	err = json.Unmarshal(r, &schemaResult)
	if err != nil {
		return err
	}

	if len(schemaResult.Errors) != 0 {
		fmt.Println()
		for _, e := range schemaResult.Errors {
			log.Printf("ERROR: %s", e.Message)
		}
		return fmt.Errorf("submit returned errors")
	}

	return nil
}

func makeRequest(ctx context.Context, url string, method string, authToken string, data io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, data)
	if err != nil {
		return nil, err
	}
	if authToken != "" {
		req.Header.Add("X-Dgraph-AuthToken", authToken)
	}
	return req, err
}
