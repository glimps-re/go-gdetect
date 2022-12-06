package gdetect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type submission struct {
	UUID    string `json:"uuid"`
	Malware bool   `json:"is_malware"`
}
type results struct {
	Count       int          `json:"count"`
	Submissions []submission `json:"submissions"`
}

func (c *Client) GetResults(ctx context.Context, from int, size int) (uuids []string, err error) {
	request, err := c.prepareRequest(ctx, "GET", "/api/lite/v2/results", nil)
	if err != nil {
		return
	}

	client := c.prepareClient(request)

	// Add request queries
	q := request.URL.Query()
	q.Add("from", fmt.Sprintf("%d", from))
	q.Add("size", fmt.Sprintf("%d", size))
	request.URL.RawQuery = q.Encode()

	resp, err := client.Do(request)
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
		err = fmt.Errorf("error unmarshaling response json, %s", err)
		return
	}
	for _, res := range results.Submissions {
		uuids = append(uuids, res.UUID)
	}

	return
}
