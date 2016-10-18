package request

import (
	"bytes"
	"io/ioutil"
	"net/http"
)

// GetFileHttp makes an http request for a file, passing the marshalled public key in the body
func GetFileHttp(uri, filename string) error {
	publicKeyJSON, privateKey, err := CreateRequest()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(publicKeyJSON))
	if err != nil {
		return err
	}

	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	decrypted, err := HandleResponse(b, privateKey)
	if err != nil {
		return err
	}

	err = WriteToFile(decrypted, filename)
	return err
}
