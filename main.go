package main

import (
	"fmt"
	"net/http"
	"io/ioutil"
	"strings"
	"log"
	"strconv"
	"sync"
	"time"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"os/signal"
	"syscall"
	"flag"
)

//
// Password service that hashes a password and keeps basic statistics
//


// Interface for the service ... allows for quick unit testing outside of http server and different implementations

type PasswordManagerInterface interface {
	Hash(pwd string) int64
	Get(id int64) []byte
	Stats() (int64, int64)
	HasPendingHashes() bool
	Shutdown()
	IsShuttingDown() bool
}

//
// Concrete service
//
type PasswordManager struct {
	sync.Mutex
	tasks map[int64][]byte		// hash results, indexed by id
								// in real life, this should be a bounded map to avoid OOM
	id int64 					// next task id
	requests int64       		// number of processed hash requests
	totalTime time.Duration     // total time spent processing requests
	pendingHashes int           // currently pending hash requests
	shuttingDown bool 			// indicates that a shutdown is in progress
}

const (
	NapTimeSec = 5*time.Second // simulates 5s processing delay
)

// Constructor
func NewPasswordManager() (* PasswordManager) {
	return &PasswordManager{tasks: make(map[int64][]byte)}
}

// Start hash, returns task id
func (pm *PasswordManager) Hash(pwd string) int64 {
	ts := time.Now() // spec didn't say if time keeping should include the 5s nap time; here it's calculated for the
	                 // whole request including nap

	pm.Lock()
	pm.pendingHashes++

	id := pm.id // next available id
	pm.id++     // update next id

	pm.Unlock()

	// need to return id immediately... start the calculation async
	go pm.calculateHash(id, pwd, ts)

	return id
}

// Calculate the hash
func (pm* PasswordManager) calculateHash(id int64, pwd string, ts time.Time) {

	time.Sleep(NapTimeSec) // sim processing

	// Simple hash ... this won't protect against dictionary attacks; needs salt etc.
	digest := sha512.New() // might want to cache
	digest.Write([]byte(pwd))
	hashedPwd := digest.Sum(nil)

	// store the has and update the total hash time
	pm.Lock()
	pm.tasks[id] = hashedPwd

	elapsed := time.Now().Sub(ts)
	pm.totalTime += elapsed

	// done with this request, updated pendingHashes and increment the total number of processed requests
	pm.pendingHashes--
	pm.requests++

	pm.Unlock()
}

// Get the hash for task id; removes the task
func (pm *PasswordManager) Get(id int64) []byte {
	pm.Lock()
	defer pm.Unlock()

	pwdHash := pm.tasks[id]
	delete(pm.tasks, id) // Spec didn't say what to do with hashes after they are retrieved ... delete to avoid OOM

	return pwdHash
}

// Returns the number of requests and avg processing time in ms
func (pm *PasswordManager) Stats() (requests int64 , avgTime int64) {

	pm.Lock()
	defer pm.Unlock()

	requests = pm.requests
	if requests > 0 {
		avgTime = (pm.totalTime.Nanoseconds() / 1000000) / requests
	}

	return
}

// Indicates if hashes are in progress
func (pm *PasswordManager) HasPendingHashes() bool {
	pm.Lock()
	defer pm.Unlock()

	return pm.pendingHashes > 0
}

// Initiate a shutdown
func (pm *PasswordManager) Shutdown() {
	pm.Lock()
	defer pm.Unlock()

	pm.shuttingDown = true
}

// Returns true if shutdown is in progress
func (pm *PasswordManager) IsShuttingDown() bool {
	pm.Lock()
	defer pm.Unlock()

	return pm.shuttingDown
}

//
// Handler Adapter
//   - Wraps REST endpoints and delegates actual work (business logic) to a PasswordManagerInterface
//   - Implemented as a type to allow different PasswordManager implementations
//

type PasswordManagerHandler struct {
	PasswordManager PasswordManagerInterface
}

func NewPasswordManagerHandler(pm PasswordManagerInterface) (*PasswordManagerHandler) {
	pwh := new(PasswordManagerHandler)
	pwh.PasswordManager = pm

	return pwh
}

// Helper that returns an HTTP error if shutdown is in progress
func (pmh PasswordManagerHandler) isShutdownPending(w http.ResponseWriter) bool {

	if pmh.PasswordManager.IsShuttingDown() {
		http.Error(w, "Shutdown is pending - request rejected", http.StatusForbidden) // TODO: Better status
		return true
	}

	return false
}

// POST /hash
func (pmh PasswordManagerHandler) hash(w http.ResponseWriter, req *http.Request) {

	if pmh.isShutdownPending(w) {
		return
	}

	// sanity checks
	if req.Method != http.MethodPost {
		http.Error(w, "Invalid method ('POST' required)", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "Can't read body", http.StatusBadRequest)
		return
	}

	data := string(body[:])
	items := strings.Split(data, "=")
	if len(items) != 2 || items[0] != "password" || len(items[1]) == 0 {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	// delegate actual work
	id := pmh.PasswordManager.Hash(items[1])

	w.WriteHeader(http.StatusAccepted) // resource not yet created
	w.Write([]byte(strconv.FormatInt(int64(id), 10))) // TODO: Better approach to convert int to []byte?

	// TODO securely destroy password
}

// GET /hash/<id>
func (pmh PasswordManagerHandler) get(w http.ResponseWriter, req *http.Request) {

	// Spec didn't say if /get should be prevented as well
	if pmh.isShutdownPending(w) {
		return
	}

	// sanity checks
	if req.Method != http.MethodGet {
		http.Error(w, "Invalid method ('GET' required)", http.StatusMethodNotAllowed)
		return
	}

	ids := req.URL.Path[6:] // strip /hash/ from /hash/1245
	id, err := strconv.ParseInt(ids, 10, 64)
	if err != nil {
		http.Error(w, "Invalid method resource id", http.StatusBadRequest)
		return
	}

	pwdHash := pmh.PasswordManager.Get(id)

	if pwdHash == nil {
		http.Error(w, "Hash not found", http.StatusNotFound)
		return
	}

	encoder := base64.NewEncoder(base64.StdEncoding, w)
	encoder.Write(pwdHash)
	encoder.Close()
}


// GET /stats
func (pmh PasswordManagerHandler) stats(w http.ResponseWriter, req *http.Request) {

	// Spec didn't say if /stats should be prevented as well
	if pmh.isShutdownPending(w) {
		return
	}

	// sanity checks
	if req.Method != http.MethodGet {
		http.Error(w, "Invalid method ('GET' required)", http.StatusMethodNotAllowed)
		return
	}

	requests, avgTime := pmh.PasswordManager.Stats()

	// JSON is very simple ... therefore just create a string
	body := fmt.Sprintf("{\"total\": %d, \"average\": %d}", requests, avgTime)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Write([]byte(body))
}

// Initiate a graceful shutdown
func (pmh PasswordManagerHandler) shutdown() {

	fmt.Println("Shutting down")
	pmh.PasswordManager.Shutdown()

	// TODO: Only wait for x seconds for graceful shutdown
	for pmh.PasswordManager.HasPendingHashes() {
		fmt.Println("Shutting down")
		time.Sleep(1*time.Second)
	}

	fmt.Println("Done")
}



func main() {
	port := flag.Int("port", 8000, "port number")
	flag.Parse()

	// DI
	var pm PasswordManagerInterface = NewPasswordManager()
	pmh := NewPasswordManagerHandler(pm)

	mux := http.NewServeMux()
	mux.Handle("/hash", http.HandlerFunc(pmh.hash))
	mux.Handle("/hash/", http.HandlerFunc(pmh.get))
	mux.Handle("/stats", http.HandlerFunc(pmh.stats))

	// Shutdown handler
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		pmh.shutdown()
		os.Exit(0)
	}()

	log.Fatal(http.ListenAndServe("localhost:"+strconv.Itoa(*port), mux))
}