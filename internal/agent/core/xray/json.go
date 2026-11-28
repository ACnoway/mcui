package xray

import "encoding/json"

func jsonUnmarshalRelaxed(raw []byte, out any) error {
	return json.Unmarshal(raw, out)
}
