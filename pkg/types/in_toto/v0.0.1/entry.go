/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package in_toto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	//"io"
	//"io/ioutil"
	"reflect"
	//"strconv"
	"strings"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki/pgp"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/in_toto"
	"github.com/sigstore/rekor/pkg/util"

	//"github.com/asaskevich/govalidator"

	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/pki"

	link "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/go-openapi/swag"
	"github.com/mitchellh/mapstructure"
	"github.com/sigstore/rekor/pkg/generated/models"
	"golang.org/x/sync/errgroup"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	in_toto.SemVerToFacFnMap.Set(APIVERSION, NewEntry)
}

type V001Entry struct {
	InTotoModel                models.InTotoV001Schema
	fetchedExternalEntities bool
	keyObj                  pki.PublicKey
	in_totoObj              *link.Metablock
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func Base64StringtoByteArray() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Slice {
			return data, nil
		}

		bytes, err := base64.StdEncoding.DecodeString(data.(string))
		if err != nil {
			return []byte{}, fmt.Errorf("failed parsing base64 data: %v", err)
		}
		return bytes, nil
	}
}

func (v V001Entry) IndexKeys() []string {
	var result []string

	if v.HasExternalEntities() {
		if err := v.FetchExternalEntities(context.Background()); err != nil {
			log.Logger.Error(err)
			return result
		}
	}

	key, err := v.keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		hasher := sha256.New()
		if _, err := hasher.Write(key); err != nil {
			log.Logger.Error(err)
		} else {
			result = append(result, strings.ToLower(hex.EncodeToString(hasher.Sum(nil))))
		}
	}

	if v.InTotoModel.Metablock.Signed.Name != nil {
		result = append(result, strings.ToLower(swag.StringValue(v.InTotoModel.Metablock.Signed.Name)))
	}

	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	in_toto, ok := pe.(*models.InToto)
	if !ok {
		return errors.New("cannot unmarshal non in-toto v0.0.1 type")
	}

	cfg := mapstructure.DecoderConfig{
		DecodeHook: Base64StringtoByteArray(),
		Result:     &v.InTotoModel,
	}

	dec, err := mapstructure.NewDecoder(&cfg)
	if err != nil {
		return fmt.Errorf("error initializing decoder: %w", err)
	}

	if err := dec.Decode(in_toto.Spec); err != nil {
		return err
	}
	// field validation
	if err := v.InTotoModel.Validate(strfmt.Default); err != nil {
		return err
	}
	// cross field validation
	return v.Validate()

}

func (v V001Entry) HasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.InTotoModel.PublicKey != nil && v.InTotoModel.PublicKey.URL.String() != "" {
		return true
	}
	return false
}

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {
	if v.fetchedExternalEntities {
		return nil
	}

	if err := v.Validate(); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	artifactFactory := pki.NewArtifactFactory("pgp")

    // FIXME: use in-toto intrinsics here.
	g.Go(func() error {
		keyReadCloser, _ := util.FileOrURLReadCloser(ctx, v.InTotoModel.PublicKey.URL.String(),
			v.InTotoModel.PublicKey.Content, false)
		defer keyReadCloser.Close()

		v.keyObj, _ = artifactFactory.NewPublicKey(keyReadCloser)
		_, err := v.keyObj.(*pgp.PublicKey).KeyRing()
//FIXME: should use Metablock.Verify(key) here instead.
//		if _, err := rpmutils.GPGCheck(sigR, keyring); err != nil {
//			return closePipesOnError(err)
//		}
        if err != nil {
            return err
        }

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	if err := g.Wait(); err != nil {
		return err
	}

	v.fetchedExternalEntities = true
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if err := v.FetchExternalEntities(ctx); err != nil {
		return nil, err
	}
	if v.keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.InTotoV001Schema{}
	canonicalEntry.ExtraData = v.InTotoModel.ExtraData

	var err error
	// need to canonicalize key content
	canonicalEntry.PublicKey = &models.InTotoV001SchemaPublicKey{}
	canonicalEntry.PublicKey.Content, err = v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

    // FIXME: what does canonicalization mean, exactly? (i.e., can se use in-toto.util.EncodeCanonical?)
    // we use in-toto links 
	//canonicalEntry.Link = &models.InTotoV001SchemaLink{}
	//canonicalEntry.Link.Hash = &models.InTotoV001SchemaLinkHash{}
	//canonicalEntry.Link.Hash.Algorithm = v.InTotoModel.Link.Hash.Algorithm
	//canonicalEntry.Link.Hash.Value = v.InTotoModel.Link.Hash.Value
	// data content is not set deliberately

	// ExtraData is copied through unfiltered
	canonicalEntry.ExtraData = v.InTotoModel.ExtraData

	// wrap in valid object with kind and apiVersion set
	in_toto := models.InToto{}
	in_toto.APIVersion = swag.String(APIVERSION)
	in_toto.Spec = &canonicalEntry

	bytes, err := json.Marshal(&in_toto)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

//Validate performs cross-field validation for fields in object
// FIXME: we can probably export ValidateMetablock on in-toto.go
func (v V001Entry) Validate() error {
	key := v.InTotoModel.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	if len(key.Content) == 0 && key.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for publicKey")
	}

	link := v.InTotoModel.Metablock
	if link == nil {
		return errors.New("missing link")
	}
	return nil
}
