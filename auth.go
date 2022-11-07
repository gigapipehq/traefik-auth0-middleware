package traefik_auth0_middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
)

type Config struct {
	Auth0Domain            string   `json:"auth0Domain"`
	Auth0Audience          string   `json:"auth0Audience"`
	ProxyHeaderName        string   `json:"proxyHeaderName"`
	ProxyHeaderValueAsJSON bool     `json:"proxyHeaderValueAsJSON"`
	ExtractKeys            []string `json:"extractKeys"`
}

func CreateConfig() *Config {
	return &Config{
		ProxyHeaderName: "X-Auth0-User",
		ExtractKeys:     []string{},
	}
}

type Plugin struct {
	next                   http.Handler
	domain                 string
	audience               string
	proxyHeaderName        string
	proxyHeaderValueAsJSON bool
	extractKeys            []string
}

func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	return &Plugin{
		next:                   next,
		domain:                 config.Auth0Domain,
		audience:               config.Auth0Audience,
		proxyHeaderName:        config.ProxyHeaderName,
		proxyHeaderValueAsJSON: config.ProxyHeaderValueAsJSON,
		extractKeys:            config.ExtractKeys,
	}, nil
}

func (e *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerURL, _ := url.Parse(fmt.Sprintf("https://%s/", e.domain))
	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)
	tokenValidator, _ := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{e.audience},
		validator.WithAllowedClockSkew(time.Minute),
	)

	errHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "Invalid token"}`))
	}
	m := jwtmiddleware.New(func(ctx context.Context, token string) (interface{}, error) {
		u, err := tokenValidator.ValidateToken(ctx, token)
		if err != nil {
			return nil, err
		}

		data := getTokenData(e.extractKeys, u.(map[string]interface{}))
		if e.proxyHeaderValueAsJSON {
			b, _ := json.Marshal(data)
			w.Header().Set(e.proxyHeaderName, string(b))
			return u, nil
		}
		w.Header().Set(e.proxyHeaderName, fmt.Sprintf("%v", data))
		return data, nil
	}, jwtmiddleware.WithErrorHandler(errHandler))
	m.CheckJWT(e.next).ServeHTTP(w, r)
}

func getTokenData(keys []string, v map[string]interface{}) interface{} {
	extractKeyValue := func(keySet []string) interface{} {
		if len(keySet) == 1 {
			return extractValueFromMap(keySet[0], v)
		}
		value := v
		for _, k := range keySet {
			extracted := extractValueFromMap(k, value)
			if v, ok := extracted.(map[string]interface{}); ok {
				value = v
				continue
			}
			return extracted
		}
		return "nil"
	}

	switch len(keys) {
	case 0:
		return v
	case 1:
		return extractKeyValue(strings.Split(keys[0], "."))
	default:
		data := make(map[string]interface{})
		for _, key := range keys {
			data[key] = extractKeyValue(strings.Split(key, "."))
		}
		return data
	}
}

func extractValueFromMap(key string, v map[string]interface{}) interface{} {
	if value, ok := v[key]; ok {
		return value
	}
	return nil
}
