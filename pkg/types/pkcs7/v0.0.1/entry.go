/*
Copyright © 2021 Dan Lorenc <lorenc.d@gmail.com>

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
package pkcs7

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	mpkcs7 "go.mozilla.org/pkcs7"

	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/pkcs7"

	"github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
	"github.com/mitchellh/mapstructure"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	pkcs7.SemVerToFacFnMap.Set(APIVERSION, NewEntry)
}

type V001Entry struct {
	PKCS7Model models.Pkcs7V001Schema
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

	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	pk, ok := pe.(*models.Pkcs7)
	if !ok {
		return errors.New("cannot unmarshal non RPM v0.0.1 type")
	}

	cfg := mapstructure.DecoderConfig{
		DecodeHook: Base64StringtoByteArray(),
		Result:     &v.PKCS7Model,
	}

	dec, err := mapstructure.NewDecoder(&cfg)
	if err != nil {
		return fmt.Errorf("error initializing decoder: %w", err)
	}

	if err := dec.Decode(pk.Spec); err != nil {
		return err
	}
	// field validation
	if err := v.PKCS7Model.Validate(strfmt.Default); err != nil {
		return err
	}
	// cross field validation
	return v.Validate()

}

func (v V001Entry) HasExternalEntities() bool {
	return false
}

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {

	p7, err := mpkcs7.Parse(*v.PKCS7Model.Content)
	if err != nil {
		return nil, err
	}

	if err := p7.Verify(); err != nil {
		return nil, err
	}

	canonicalEntry := models.Pkcs7V001Schema{}
	// canonicalEntry.ExtraData = v.PKCS7Model.ExtraData

	// Pass it through for now. Eventually marshal/unmarshal
	canonicalEntry.Content = v.PKCS7Model.Content

	// wrap in valid object with kind and apiVersion set
	pk := models.Pkcs7{}
	pk.APIVersion = swag.String(APIVERSION)
	pk.Spec = &canonicalEntry

	bytes, err := json.Marshal(&pk)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

//Validate performs cross-field validation for fields in object
func (v V001Entry) Validate() error {
	return nil
}
