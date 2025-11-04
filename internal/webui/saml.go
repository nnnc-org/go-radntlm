package webui

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

type SAMLConfig struct {
	Domain       string
	MetadataURL  string
	MetadataFile string
	CertFile     string
	KeyFile      string
}

func setupSAML(samlConfig SAMLConfig) (*samlsp.Middleware, error) {
	if samlConfig.Domain == "" {
		return nil, errors.New("SAML domain must be provided")
	}
	// if no scheme, add http
	rootURLStr := samlConfig.Domain
	if len(rootURLStr) < 7 || (rootURLStr[:7] != "http://" && rootURLStr[:8] != "https://") {
		rootURLStr = "http://" + rootURLStr
	}

	rootURL, err := url.Parse(rootURLStr + "/")
	if err != nil {
		return nil, err
	}

	// load signing certificate
	signingCert, err := getSigningCert(samlConfig.Domain, samlConfig.CertFile, samlConfig.KeyFile)
	if err != nil {
		return nil, err
	}

	// check for metadata source
	idpMetadata, err := getSamlMetadata(samlConfig)
	if err != nil {
		return nil, err
	}

	opts := samlsp.Options{
		URL:               *rootURL,
		EntityID:          rootURL.String() + "saml/metadata",
		IDPMetadata:       idpMetadata,
		AllowIDPInitiated: true,
		Certificate:       signingCert.Leaf,
		Key:               signingCert.PrivateKey.(*rsa.PrivateKey),
	}

	sp, err := samlsp.New(opts)
	if err != nil {
		return nil, err
	}

	sp.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat

	return sp, nil

}

// helper for getting env vars
func getEnv(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func getSamlMetadata(s SAMLConfig) (*saml.EntityDescriptor, error) {
	// check for metadata source
	if s.MetadataURL == "" && s.MetadataFile == "" {
		return nil, errors.New("either SAML metadata URL or metadata file must be provided")
	} else if s.MetadataURL != "" {
		// load metadata from URL
		idpMetadataURL, err := url.Parse(s.MetadataURL)
		if err != nil {
			panic(err) // TODO handle error
		}
		return samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	} else if s.MetadataFile != "" {
		// load metadata from file
		data, err := os.ReadFile(s.MetadataFile)
		if err != nil {
			return nil, err
		}
		return samlsp.ParseMetadata(data)
	}
	return nil, errors.New("invalid SAML configuration")
}
