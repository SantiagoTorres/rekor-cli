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
	"errors"
	"fmt"

	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/util"

	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	KIND = "in_toto"
)

type BaseInTotoType struct{}

func (rt BaseInTotoType) Kind() string {
	return KIND
}

func init() {
	types.TypeMap.Set(KIND, New)
}

func New() types.TypeImpl {
	return &BaseInTotoType{}
}

var SemVerToFacFnMap = &util.VersionFactoryMap{VersionFactories: make(map[string]util.VersionFactory)}

func (rt BaseInTotoType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	in_toto, ok := pe.(*models.InToto)
	if !ok {
		return nil, errors.New("cannot unmarshal non-in-toto types")
	}

	if genFn, found := SemVerToFacFnMap.Get(swag.StringValue(in_toto.APIVersion)); found {
		entry := genFn()
		if entry == nil {
			return nil, fmt.Errorf("failure generating in_toto object for version '%v'", in_toto.APIVersion)
		}
		if err := entry.Unmarshal(in_toto); err != nil {
			return nil, err
		}
		return entry, nil
	}
	return nil, fmt.Errorf("InTotoType implementation for version '%v' not found", swag.StringValue(in_toto.APIVersion))
}
