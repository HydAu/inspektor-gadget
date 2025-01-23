// Copyright 2024 The Inspektor Gadget authors
//
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

package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetStart
func gadgetStart() int {
	ds, err := api.GetDataSource("containers")
	if err != nil {
		api.Errorf("Failed to get data source: %v", err)
		return 1
	}

	idField, err := ds.GetField("id")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	nameField, err := ds.GetField("name")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	ds.Subscribe(func(ds api.DataSource, data api.Data) {
		id, err := idField.String(data)
		if err != nil {
			return
		}
		name, err := nameField.String(data)
		if err != nil {
			return
		}

		api.Infof("FROM WASM IN GADGET: created container %s: %s", id, name)
	}, 0)

	return 0
}

func main() {}
