// Copyright © 2020 Weald Technology Trading.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vault

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"

	vault "github.com/hashicorp/vault/api"
	awsAuth "github.com/hashicorp/vault/api/auth/aws"
	k8sAuth "github.com/hashicorp/vault/api/auth/kubernetes"
)

// Service returns values from Amazon secrets manager.
// This service handles URLs with the scheme "asm".
// A full URL is of the form "asm://id:secret@region/secret".
// ID and secret can be supplied at creation time if preferred.
// region can also be supplied at creation time if preferred.
// If both are supplied URLs are of the form "asm:///secret".
// Any provision of ID and secret or of region will override the defaults.
type Service struct {
	credentialsCache map[string]string
	vaultToken       string
}

// module-wide log.
var log zerolog.Logger

// New creates a new Amazon Secrets Manager confidant.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "confidant").Str("impl", "vault").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	cache := make(map[string]string)
	s := &Service{
		credentialsCache: cache,
	}

	return s, nil
}

// SupportedURLSchemes provides the list of schemes supported by this confidant.
func (s *Service) SupportedURLSchemes(ctx context.Context) ([]string, error) {
	return []string{"vault"}, nil
}

//kv
// vault://vault.prod.stake.capital:8200/kv?use_ssl={true|false}&auth_method={auth_method}&auth_path={auth_path}&kv={kv_path}&secret_path={secret_path}
// vault://vault.prod.stake.capital:8200/pki?use_ssl={true|false}&auth_method={auth_method}&pki={pki_path}&common_name={secret_path}

// Fetch fetches a value given its key.
func (s *Service) Fetch(ctx context.Context, url *url.URL) ([]byte, error) {

	secretKey := url.String()
	if val, ok := s.credentialsCache[secretKey]; ok {
		if ok {
			return []byte(val), nil
		}
	}

	host := url.Host
	if host == "" {
		return nil, errors.New("no vault specified")
	}

	port := url.Port()
	if port == "" {
		port = "8200"
	}

	module := url.Path
	if module == "" {
		return nil, errors.New("no vault module specified")
	}

	if module != "kv" && module != "pki" {
		return nil, errors.New("unknown vault module. Only (kv|pki) are allowed")
	}

	authMethod := url.Query().Get("auth_method")
	if authMethod == "" {
		authMethod = "kubernetes"
	}

	if authMethod != "kubernetes" && authMethod != "aws_iam_role" && authMethod != "aws_ec2" {
		return nil, errors.New("unknown vault auth method. Only (kubernetes|aws_iam_role|aws_ec2) are allowed")
	}

	authPath := url.Query().Get("auth_path")
	if authPath == "" {
		authPath = authMethod
	}

	kubeSaToken := url.Query().Get("kube_sa_token")
	if kubeSaToken == "" {
		kubeSaToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	useSsl := url.Query().Get("use_ssl")
	scheme := ""
	if useSsl == "true" {
		scheme = "https"
	} else {
		scheme = "http"
	}

	// If set, the VAULT_ADDR environment variable will be the address that
	// your pod uses to communicate with Vault.
	config := vault.DefaultConfig() // modify for more granular configuration
	config.Address = fmt.Sprintf("%s://%s:%s", scheme, host, port)

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to initialize Vault client: %w", err))
	}

	switch authMethod {
	case "token":
		s.vaultToken = url.Query().Get("vault_token")
		if s.vaultToken == "" {
			return nil, errors.New("unable to load Vault token")
		}
		break
	case "kubernetes":
		// The service-account token will be read from the path where the token's
		// Kubernetes Secret is mounted. By default, Kubernetes will mount it to
		// /var/run/secrets/kubernetes.io/serviceaccount/token, but an administrator
		// may have configured it to be mounted elsewhere.
		// In that case, we'll use the option WithServiceAccountTokenPath to look
		// for the token there.
		kubeAuthRole := url.Query().Get("kube_auth_role")
		k8s, err := k8sAuth.NewKubernetesAuth(
			kubeAuthRole,
			k8sAuth.WithMountPath(authPath),
			k8sAuth.WithServiceAccountTokenPath(kubeSaToken),
		)
		if err != nil {
			return nil, err
		}

		authInfo, err := client.Auth().Login(context.Background(), k8s)
		if err != nil {
			return nil, err
		}
		if authInfo == nil {
			return nil, errors.New("no auth info was returned after login")
		}

		s.vaultToken = authInfo.Auth.ClientToken
		break
	case "aws_iam_role":
		awsIamRole := url.Query().Get("aws_iam_role")
		aws, err := awsAuth.NewAWSAuth(
			awsAuth.WithRole(awsIamRole), // if not provided, Vault will fall back on looking for a role with the IAM role name if you're using the iam auth type, or the EC2 instance's AMI id if using the ec2 auth type
		)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("unable to initialize AWS auth method: %w", err))
		}

		authInfo, err := client.Auth().Login(context.Background(), aws)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("unable to login to AWS auth method: %w", err))
		}
		if authInfo == nil {
			return nil, errors.New("no auth info was returned after login")
		}

		s.vaultToken = authInfo.Auth.ClientToken
		break
	case "aws_ec2":
		aws, err := awsAuth.NewAWSAuth(
			awsAuth.WithEC2Auth(), // if not provided, Vault will fall back on looking for a role with the IAM role name if you're using the iam auth type, or the EC2 instance's AMI id if using the ec2 auth type
		)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("unable to initialize AWS auth method: %w", err))
		}

		authInfo, err := client.Auth().Login(context.Background(), aws)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("unable to login to AWS auth method: %w", err))
		}
		if authInfo == nil {
			return nil, errors.New("no auth info was returned after login")
		}

		break
	}

	client.SetToken(s.vaultToken)
	kvPath := url.Query().Get("kv_path")
	secretPath := url.Query().Get("secret_path")
	kvKey := url.Query().Get("kv_key")
	if kvKey == "" {
		kvKey = "data"
	}

	// get secret from the default mount path for KV v2 in dev mode, "secret"
	secret, err := client.KVv2(kvPath).Get(context.Background(), secretPath)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to read secret: %w", err))
	}

	// data map can contain more than one key-value pair,
	// in this case we're just grabbing one of them
	value, ok := secret.Data[kvKey].(string)
	if !ok {
		return nil, errors.New(fmt.Sprintf("value type assertion failed: %T %#v", secret.Data[kvKey], secret.Data[kvKey]))
	}

	s.credentialsCache[secretKey] = value
	return []byte(value), nil
}
