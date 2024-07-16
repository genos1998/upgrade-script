package graphqlfunc

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Khan/genqlient/graphql"
)

const OpsmxAuthHeader = "X-OpsMx-Auth"

type authedTransport struct {
	token   string
	wrapped http.RoundTripper
}

func (t *authedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(OpsmxAuthHeader, t.token)
	return t.wrapped.RoundTrip(req)
}

func NewClient(graphqlUrl, graphqlToken string) graphql.Client {

	graphqlUrl = fmt.Sprintf("%s/graphql", graphqlUrl)

	httpClient := http.Client{
		Timeout: 30 * time.Second,
		Transport: &authedTransport{
			token:   graphqlToken,
			wrapped: http.DefaultTransport,
		},
	}

	return graphql.NewClient(graphqlUrl, &httpClient)
}
