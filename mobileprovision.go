package main

import (
	"fmt"

	"github.com/DHowett/go-plist"
)

func parseProvisioningProfile(b []byte) (map[string]interface{}, error) {
	data := map[string]interface{}{}
	_, err := plist.Unmarshal(b, &data)
	if err != nil {
		return nil, fmt.Errorf("plist unmarshal error: %s", err)
	}
	return data, nil
}
