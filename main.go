package main

import (
	"flag"
	"log"
	"net/http"
	"net/url"

	"github.com/stinkyfingers/fileEncryption/request"
	"github.com/stinkyfingers/fileEncryption/respond"
)

var (
	uri         = flag.String("uri", "http://localhost:9000", "-uri=filelocation")
	fileToGet   = flag.String("fetch", "test.txt", "-fetch=<filename_to_get>")
	fileToWrite = flag.String("write", "temp.txt", "-write=<file_to_write>")
	port        = flag.String("port", "9000", "-port=<port>")
)

func main() {
	flag.Parse()

	// run response server
	go server()

	// parse url & query
	u, err := url.Parse(*uri)
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	q.Add("file", *fileToGet)
	u.RawQuery = q.Encode()

	// get & decrypt file
	err = request.GetFileHttp(u.String(), *fileToWrite)
	if err != nil {
		log.Fatal(err)
	}

}

// server for the responder
func server() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", respond.HandleRequest)
	log.Fatal(http.ListenAndServe(":"+*port, mux))
}
