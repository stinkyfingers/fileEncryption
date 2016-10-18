package respond

import (
	"io/ioutil"
	"net/http"
)

// HandleRequest gets a public key from JSON in the request body and the filename from the
// query and writes encrypted contents
func HandleRequest(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	publicKeyJSON, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	j, err := EncryptContents(contents, publicKeyJSON)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(j)
}
