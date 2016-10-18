package request

import (
	"testing"
)

func TestCreateRequest(t *testing.T) {
	publicJSON, private, err := CreateRequest()
	if err != nil {
		t.Error(err)
	}
	t.Log(publicJSON, private)
}
