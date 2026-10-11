package sally

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// PairStartRequest identifies this PC to the (unauthenticated) pairing route.
type PairStartRequest struct {
	DeviceName   string `json:"deviceName"`
	Platform     string `json:"platform"` // windows | mac | linux
	AgentVersion string `json:"agentVersion"`
	Capability   string `json:"capability"` // always "SCAN"
}

// PairStartResponse is the code to show and the secret code to poll with.
type PairStartResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expiresIn"`
}

// Paired is the result of an approved pairing.
type Paired struct {
	Token       string
	DeviceID    string
	CompanyID   string
	CompanyName string
}

type pollResponse struct {
	Status string `json:"status"`
	Token  string `json:"token"`
	Device *struct {
		ID                 string   `json:"id"`
		ApprovedCompanyIDs []string `json:"approvedCompanyIds"`
		Capability         string   `json:"capability"`
	} `json:"device"`
	CompanyName string `json:"companyName"`
}

// PairError is a pairing that ended without approval.
type PairError struct{ Status string }

func (e *PairError) Error() string {
	switch e.Status {
	case "denied":
		return "the connection was refused in Sally"
	case "expired":
		return "the code expired before it was approved"
	default:
		return "pairing ended: " + e.Status
	}
}

// PairStart asks Sally for a code.
func (c *Client) PairStart(ctx context.Context, req PairStartRequest) (*PairStartResponse, error) {
	req.Capability = "SCAN"
	var out PairStartResponse
	if _, err := c.call(ctx, http.MethodPost, "/api/agent/pair/start", nil, req, &out); err != nil {
		return nil, err
	}
	if out.DeviceCode == "" || out.UserCode == "" {
		return nil, errors.New("sally: pairing answer had no code")
	}
	return &out, nil
}

// pollOnce polls the pairing once. 404 carries {status: "not_found"}.
func (c *Client) pollOnce(ctx context.Context, deviceCode string) (*pollResponse, error) {
	var out pollResponse
	_, err := c.call(ctx, http.MethodPost, "/api/agent/pair/poll", nil, map[string]string{"deviceCode": deviceCode}, &out)
	if err != nil {
		if StatusOf(err) == http.StatusNotFound {
			return &pollResponse{Status: "not_found"}, nil
		}
		return nil, err
	}
	return &out, nil
}

// Pair runs the device grant: it asks for a code, hands it to show (which
// opens the browser at verificationUriComplete and puts the code on the
// status page), and polls until the person approves, refuses, or the code
// expires.
func (c *Client) Pair(ctx context.Context, req PairStartRequest, show func(*PairStartResponse)) (*Paired, error) {
	start, err := c.PairStart(ctx, req)
	if err != nil {
		return nil, err
	}
	if show != nil {
		show(start)
	}
	interval := time.Duration(start.Interval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}
	if c.pollEvery > 0 {
		interval = c.pollEvery
	}
	expires := 15 * time.Minute
	if start.ExpiresIn > 0 {
		expires = time.Duration(start.ExpiresIn) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, expires+interval)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, &PairError{Status: "expired"}
			}
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		res, err := c.pollOnce(ctx, start.DeviceCode)
		if err != nil {
			var rl *RateLimitError
			if errors.As(err, &rl) {
				// Slow down as asked, and stay slower.
				if c.pollEvery == 0 {
					interval += 5 * time.Second
					if rl.RetryAfter > interval {
						interval = rl.RetryAfter
					}
				}
				continue
			}
			// A network blip while waiting for a person is normal; keep
			// polling until the code expires.
			continue
		}
		switch res.Status {
		case "pending", "":
			continue
		case "approved":
			if res.Token == "" || res.Device == nil || len(res.Device.ApprovedCompanyIDs) == 0 {
				return nil, fmt.Errorf("sally: approval came without a token or company")
			}
			return &Paired{
				Token:       res.Token,
				DeviceID:    res.Device.ID,
				CompanyID:   res.Device.ApprovedCompanyIDs[0],
				CompanyName: res.CompanyName,
			}, nil
		default:
			return nil, &PairError{Status: res.Status}
		}
	}
}
