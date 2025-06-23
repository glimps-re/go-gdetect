package gdetect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
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
	q.Add("from", strconv.Itoa(from))
	q.Add("size", strconv.Itoa(size))
	if len(tags) > 0 {
		q.Add("tags", tags[0])
	}

	request.URL.RawQuery = q.Encode()

	resp, err := c.doRequest(ctx, request, []int{http.StatusOK, http.StatusNotFound},
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	)
	if err != nil {
		return
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	defer func() {
		if e := resp.Body.Close(); e != nil {
			Logger.Error("could not close response body", slog.String("error", e.Error()))
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
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
