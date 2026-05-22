package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GCloudMetrics holds data retrieved from Google Cloud Monitoring API or local inferences.
type GCloudMetrics struct {
	ActiveExecutions  int64 `json:"active_executions"`
	DailyRequestsUsed int64 `json:"daily_requests_used"`
	DailyRequestsMax  int64 `json:"daily_requests_max"`
	ErrorCount5xx     int64 `json:"error_count_5xx"`
	RateLimitHits     int64 `json:"rate_limit_hits"`
}

// RefreshAccessToken exchanges a Google OAuth Refresh Token for a fresh Access Token.
func RefreshAccessToken(clientID, clientSecret, refreshToken string) (string, error) {
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		return "", fmt.Errorf("missing OAuth credentials")
	}

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	return result.AccessToken, nil
}

// FetchGoogleCloudMetrics queries the Google Cloud Monitoring API for Apps Script usage statistics.
// If credentials are empty or query fails, it returns inferred metrics based on the SQLite DB node history.
func FetchGoogleCloudMetrics(accessToken string, projectID string) (GCloudMetrics, error) {
	if accessToken == "" || projectID == "" {
		return GCloudMetrics{}, fmt.Errorf("missing access token or Google Cloud project ID")
	}

	// Example Metric Query: script.googleapis.com/servicing/executing_time or generic cloud functions
	// We call standard Stackdriver Monitoring v3 API
	timeSeriesURL := fmt.Sprintf("https://monitoring.googleapis.com/v3/projects/%s/timeSeries", projectID)

	// Fetch execution counts for the last 24h
	now := time.Now().UTC()
	startTime := now.Add(-24 * time.Hour)

	u, _ := url.Parse(timeSeriesURL)
	q := u.Query()
	q.Set("filter", `metric.type="script.googleapis.com/servicing/executing_time"`)
	q.Set("interval.startTime", startTime.Format(time.RFC3339))
	q.Set("interval.endTime", now.Format(time.RFC3339))
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return GCloudMetrics{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return GCloudMetrics{}, fmt.Errorf("monitoring API failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse Google Cloud Monitoring response
	var googleMetricResponse struct {
		TimeSeries []struct {
			Points []struct {
				Value struct {
					Int64Value string `json:"int64Value"`
				} `json:"value"`
			} `json:"points"`
		} `json:"timeSeries"`
	}

	err = json.NewDecoder(resp.Body).Decode(&googleMetricResponse)
	if err != nil {
		return GCloudMetrics{}, err
	}

	var executions int64
	for _, series := range googleMetricResponse.TimeSeries {
		for _, pt := range series.Points {
			var val int64
			fmt.Sscanf(pt.Value.Int64Value, "%d", &val)
			executions += val
		}
	}

	return GCloudMetrics{
		ActiveExecutions:  executions,
		DailyRequestsUsed: executions, // Approx requests matching script runs
		DailyRequestsMax:  20000,      // Google Apps Script standard quota per day
	}, nil
}

// InferMetricsFromDB creates smart inferred metrics based on local proxy performance history.
func InferMetricsFromDB(nodes []GASNodeModel) GCloudMetrics {
	var totalSent int64
	var totalFailed int64
	var rateLimits int64

	for _, node := range nodes {
		totalSent += node.TotalRequestsSent
		totalFailed += node.FailedRequests
		if node.Status == "Quota_Exceeded" {
			rateLimits++
		}
	}

	return GCloudMetrics{
		ActiveExecutions:  0,
		DailyRequestsUsed: totalSent,
		DailyRequestsMax:  int64(len(nodes)) * 20000, // Total possible quota
		ErrorCount5xx:     totalFailed,
		RateLimitHits:     rateLimits,
	}
}

// ExtractProjectID extracts the likely GCP Project ID from Google Script URLs or settings.
// Since Apps Script runs in standard script containers, users can link them to GCP projects.
func ExtractProjectID(gcpProject string) string {
	return strings.TrimSpace(gcpProject)
}
