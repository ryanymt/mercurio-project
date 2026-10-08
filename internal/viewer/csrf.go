package viewer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// A form's CSRF token is HMAC(key, email, act, ticket, issued-at), valid for an hour (D17). The key
// is a secret every instance reads, so a token made by one verifies in another, and after a scale
// to zero (critique G2, red team R6). IAP's session cookie travels with a cross-site POST; this
// token, and the Sec-Fetch-Site or Origin check, are what refuse one.

const (
	csrfLifetime = time.Hour
	csrfSkew     = time.Minute // a token issued this far ahead of this instance's clock still verifies
)

// The acts a token is for.
const (
	actCreate = "create"
	actDecide = "decide"
	actPark   = "park"
)

func (s *Server) csrfMAC(email, act string, ticket, issued int64) string {
	m := hmac.New(sha256.New, s.cfg.CSRFKey)
	m.Write([]byte(strings.Join([]string{email, act, strconv.FormatInt(ticket, 10), strconv.FormatInt(issued, 10)}, "\x00")))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// csrfToken is "issued.mac", for this person, act and ticket (0 for none).
func (s *Server) csrfToken(email, act string, ticket int64) string {
	issued := s.cfg.Now().Unix()
	return strconv.FormatInt(issued, 10) + "." + s.csrfMAC(email, act, ticket, issued)
}

// csrfValid checks a token for this person, act and ticket, issued within the hour.
func (s *Server) csrfValid(token, email, act string, ticket int64) bool {
	raw, mac, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	issued, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false
	}
	if !hmac.Equal([]byte(mac), []byte(s.csrfMAC(email, act, ticket, issued))) {
		return false
	}
	at := time.Unix(issued, 0)
	now := s.cfg.Now()
	return !at.After(now.Add(csrfSkew)) && now.Sub(at) <= csrfLifetime
}
