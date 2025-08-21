/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implieclient.
See the License for the specific language governing permissions and
limitations under the License.
*/

package doppler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	dClient "github.com/external-secrets/external-secrets/pkg/provider/doppler/client"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

const (
	errNewClient    = "unable to create DopplerClient : %s"
	errInvalidStore = "invalid store: %s"
	errDopplerStore = "missing or invalid Doppler SecretStore"
)

// Provider is a Doppler secrets provider implementing NewClient and ValidateStore for the esv1.Provider interface.
type Provider struct{}

// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1.SecretsClient = &Client{}
var _ esv1.Provider = &Provider{}

func init() {
	esv1.Register(&Provider{}, &esv1.SecretStoreProvider{
		Doppler: &esv1.DopplerProvider{},
	}, esv1.MaintenanceStatusMaintained)
}

func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
}

func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {
	var err error
	var retryAmount = 0
	var retryDuration = 0 * time.Second

	storeSpec := store.GetSpec()

	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.Doppler == nil {
		return nil, errors.New(errDopplerStore)
	}

	dopplerStoreSpec := storeSpec.Provider.Doppler

	// Default Key to dopplerToken if not specified
	if dopplerStoreSpec.Auth.SecretRef.DopplerToken.Key == "" {
		storeSpec.Provider.Doppler.Auth.SecretRef.DopplerToken.Key = "dopplerToken"
	}

	// Setup retry options, but only if present
	if storeSpec.RetrySettings != nil {
		if storeSpec.RetrySettings.MaxRetries != nil {
			retryAmount = int(*storeSpec.RetrySettings.MaxRetries)
		} else {
			retryAmount = 3
		}

		if storeSpec.RetrySettings.RetryInterval != nil {
			retryDuration, err = time.ParseDuration(*storeSpec.RetrySettings.RetryInterval)
		} else {
			retryDuration = 5 * time.Second
		}

		if err != nil {
			return nil, fmt.Errorf(errNewClient, err)
		}
	}

	client := &Client{
		retryAmount:   retryAmount,
		retryDuration: retryDuration,

		kube:      kube,
		store:     dopplerStoreSpec,
		namespace: namespace,
		storeKind: store.GetObjectKind().GroupVersionKind().Kind,
	}

	if err := client.setAuth(ctx); err != nil {
		return nil, err
	}

	doppler, err := dClient.NewDopplerClient(client.dopplerToken, client.retryAmount, client.retryDuration)
	if err != nil {
		return nil, fmt.Errorf(errNewClient, err)
	}

	if customBaseURL, found := os.LookupEnv(customBaseURLEnvVar); found {
		if err := doppler.SetBaseURL(customBaseURL); err != nil {
			return nil, fmt.Errorf(errNewClient, err)
		}
	}

	if customVerifyTLS, found := os.LookupEnv(verifyTLSOverrideEnvVar); found {
		customVerifyTLS, err := strconv.ParseBool(customVerifyTLS)
		if err == nil {
			doppler.VerifyTLS = customVerifyTLS
		}
	}

	client.doppler = doppler
	client.project = client.store.Project
	client.config = client.store.Config
	client.nameTransformer = client.store.NameTransformer
	client.format = client.store.Format

	return client, nil
}

func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	storeSpec := store.GetSpec()
	dopplerStoreSpec := storeSpec.Provider.Doppler
	dopplerTokenSecretRef := dopplerStoreSpec.Auth.SecretRef.DopplerToken
	if err := utils.ValidateSecretSelector(store, dopplerTokenSecretRef); err != nil {
		return nil, fmt.Errorf(errInvalidStore, err)
	}

	if dopplerTokenSecretRef.Name == "" {
		return nil, fmt.Errorf(errInvalidStore, "dopplerToken.name cannot be empty")
	}

	return nil, nil
}
