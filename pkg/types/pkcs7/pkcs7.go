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
	"errors"
	"fmt"

	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/util"

	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	KIND = "pkcs7"
)

type BasePKCS7Type struct{}

func (pt BasePKCS7Type) Kind() string {
	return KIND
}

func init() {
	types.TypeMap.Set(KIND, New)
}

func New() types.TypeImpl {
	return &BasePKCS7Type{}
}

var SemVerToFacFnMap = &util.VersionFactoryMap{VersionFactories: make(map[string]util.VersionFactory)}

func (pt BasePKCS7Type) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	pk, ok := pe.(*models.Pkcs7)
	if !ok {
		return nil, errors.New("cannot unmarshal non-PKCS7 types")
	}

	if genFn, found := SemVerToFacFnMap.Get(swag.StringValue(pk.APIVersion)); found {
		entry := genFn()
		if entry == nil {
			return nil, fmt.Errorf("failure generating RPM object for version '%v'", pk.APIVersion)
		}
		if err := entry.Unmarshal(pk); err != nil {
			return nil, err
		}
		return entry, nil
	}
	return nil, fmt.Errorf("PKCS7Type implementation for version '%v' not found", swag.StringValue(pk.APIVersion))
}
