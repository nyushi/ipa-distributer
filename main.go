package main

import (
	"archive/zip"
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fullsailor/pkcs7"
	"github.com/k0kubun/pp"
)

type apiError struct {
	Error  error
	Status int
}

var (
	appIdentifier string
	dataDir       string
	debug         bool
)

func init() {
	flag.StringVar(&appIdentifier, "appid", "", "")
	flag.BoolVar(&debug, "debug", false, "debug flag")
	flag.StringVar(&dataDir, "data-dir", ".", "data diretory")
}
func httpAPI(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/upload" && req.Method == http.MethodPut {
		status := http.StatusOK
		if apierr := uploadAPI(w, req); apierr != nil {
			log.Printf("error at upload: %s", apierr.Error)
			status = apierr.Status
		}
		w.WriteHeader(status)
		w.Write([]byte(http.StatusText(status)))
		return
	}
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	fmt.Fprintf(w, "Welcome to the home page!")
}

func uploadAPI(w http.ResponseWriter, req *http.Request) *apiError {
	tmpfile, err := ioutil.TempFile("", "uploading.*")
	if err != nil {
		return &apiError{
			fmt.Errorf("create tmpfile: %s", err),
			http.StatusInternalServerError,
		}
	}
	defer os.Remove(tmpfile.Name())
	h := sha1.New()
	teeBody := io.TeeReader(req.Body, h)
	if _, err := io.Copy(tmpfile, teeBody); err != nil {
		return &apiError{
			fmt.Errorf("copy to tmpfile: %s", err),
			http.StatusInternalServerError,
		}
	}
	filename := fmt.Sprintf("%x", h.Sum(nil))
	path := filepath.Join(dataDir, filename)
	if debug {
		fmt.Println(path)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return &apiError{
			fmt.Errorf("%s is already exists", path),
			http.StatusBadRequest,
		}
	}

	if err := os.Rename(tmpfile.Name(), path); err != nil {
		return &apiError{
			fmt.Errorf("failed to rename tmpfile: %s", err),
			http.StatusInternalServerError,
		}
	}

	if err := zipCheck(path); err != nil {
		return &apiError{
			fmt.Errorf("error at ipa check: %s", err),
			http.StatusBadRequest,
		}
	}

	return nil
}

func zipCheck(path string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open zip: %s", err)
	}
	defer r.Close()
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, "embedded.mobileprovision") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open file in zip: %s %s", f.Name, err)
		}
		xmldata, err := loadPKCS7Content(rc)
		if err != nil {
			return fmt.Errorf("smime error: %s %s", f.Name, err)
		}
		profile, err := parseProvisioningProfile(xmldata)
		if err != nil {
			return fmt.Errorf("failed to parse mobileprovision xml: %s", err)
		}
		if debug {
			pp.Println(profile)
		}
		appID := profile["Entitlements"].(map[string]interface{})["application-identifier"]
		if appID != appIdentifier {
			return fmt.Errorf("invalid appid: `%s` but `%s` is expected", appID, appIdentifier)
		}
	}
	return nil
}

func loadPKCS7Content(r io.Reader) ([]byte, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read pkcs7 data: %s", err)
	}
	msg, err := pkcs7.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pkcs7: %s", err)
	}
	if err := msg.Verify(); err != nil {
		return nil, fmt.Errorf("failed to verify: %s", err)
	}
	return msg.Content, nil
}

func main() {
	flag.Parse()
	mustDataDirExists()
	mux := http.NewServeMux()
	mux.HandleFunc("/", httpAPI)

	s := &http.Server{
		Addr:           ":8080",
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}

func mustDataDirExists() {
	fInfo, err := os.Stat(dataDir)
	if err != nil {
		panic(fmt.Sprintf("stat error for %s", dataDir))
	}
	if !fInfo.IsDir() {
		panic(fmt.Sprintf("%s is not dir", dataDir))
	}
}
