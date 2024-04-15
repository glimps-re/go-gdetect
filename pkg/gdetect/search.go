package gdetect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type results struct {
	Count       int          `json:"count"`
	Submissions []Submission `json:"submissions"`
}

func (c *Client) GetResults(ctx context.Context, from int, size int, tags ...string) (submissions []Submission, err error) {
	request, err := c.prepareRequest(ctx, "GET", "/api/lite/v2/results", nil)
	if err != nil {
		return
	}

	// Add request queries
	q := request.URL.Query()
	q.Add("from", fmt.Sprintf("%d", from))
	q.Add("size", fmt.Sprintf("%d", size))
	if len(tags) > 0 {
		q.Add("tags", tags[0])
	}

	request.URL.RawQuery = q.Encode()

	resp, err := c.HttpClient.Do(request)
	if err != nil {
		return
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	// server return a 404 status when no result is found
	case http.StatusNotFound:
		return
	case http.StatusOK:
		break
	default:
		err = fmt.Errorf("invalid response from endpoint, %s: %s", resp.Status, string(rawBody))
		return
	}

	var results results
	err = json.Unmarshal(rawBody, &results)
	if err != nil {
		err = fmt.Errorf("error unmarshaling response json, %w", err)
		return
	}
	submissions = append(submissions, results.Submissions...)
	return
}
