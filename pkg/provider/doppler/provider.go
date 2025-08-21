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
	"github.com/external-secrets/external-secrets/pkg/provider/doppler/safecache"
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

// We have to use a global variable for the cache because a new provider client
// is created for each request in the reconcile loop. We keep a separate cache
// for each SecretStore to allow for separate TTLs.
var globalCache = make(map[string]*safecache.SafeCache)

func init() {
	esv1.Register(&Provider{}, &esv1.SecretStoreProvider{
		Doppler: &esv1.DopplerProvider{},
	}, esv1.MaintenanceStatusMaintained)
}

func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
}

func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {
	storeSpec := store.GetSpec()

	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.Doppler == nil {
		return nil, errors.New(errDopplerStore)
	}

	dopplerStoreSpec := storeSpec.Provider.Doppler

	// Default Key to dopplerToken if not specified
	if dopplerStoreSpec.Auth.SecretRef.DopplerToken.Key == "" {
		storeSpec.Provider.Doppler.Auth.SecretRef.DopplerToken.Key = "dopplerToken"
	}

	client := &Client{
		kube:      kube,
		store:     dopplerStoreSpec,
		namespace: namespace,
		storeKind: store.GetObjectKind().GroupVersionKind().Kind,
	}

	// Enable response caching based on the user's configuration. The user can either
	// not specify any cache settings at all (which will result in no caching being
	// used), can specify a cache configuration that has `enable` set to false (which
	// will result in no caching being used), or can specify settings and enable the
	// caching. Internally, we determines if the cache is used by a combination of
	// client.cache being nil (or not) and if it isn't nil, whether cache.Enabled()
	// returns true.
	if storeSpec.Provider.Doppler.Cache != nil && storeSpec.Provider.Doppler.Cache.Enable != nil && *storeSpec.Provider.Doppler.Cache.Enable {
		dopplerStoreUID := string(store.GetObjectMeta().UID)
		if globalCache[dopplerStoreUID] == nil {
			globalCache[dopplerStoreUID] = safecache.NewCache()
		}
		client.cache = globalCache[dopplerStoreUID]
		client.cache.Enable()

		// The safecache.defaultCacheEntryTTL is used for the entry TTL unless the
		// user provides their own value.
		if storeSpec.Provider.Doppler.Cache.TTL != nil {
			newTTL := time.Duration(*storeSpec.Provider.Doppler.Cache.TTL) * time.Second
			client.cache.SetCacheEntryTTL(newTTL)
		}
	}

	if err := client.setAuth(ctx); err != nil {
		return nil, err
	}

	doppler, err := dClient.NewDopplerClient(client.dopplerToken, client.cache)
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
