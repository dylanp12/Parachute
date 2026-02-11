package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","method":"%s","path":"%s","body_len":%d}`, r.Method, r.URL.Path, len(body))
	})

	fmt.Printf("Echo server listening on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}
