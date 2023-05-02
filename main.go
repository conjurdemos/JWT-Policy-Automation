package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	enc "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// JSON STRUCTS

type secret struct {
	Path string `json:"id"`
}


type config struct{
	Configuration struct {
		Conjur struct {
			Account string
		}
	}
}

type token struct {
	Access_token string `json:"access_token"`
	Token_type   string `json:"token_type"`
	Expires_in   int    `json:"expires_in"`
}

type safeObject struct {
	Retention int    `json:"numberOfDaysRetention"`
	Safe      string `json:"safeName"`
	Desc      string `json:"description"`
}

type safeperm struct {
	ManageSafe              bool `json:"manageSafe"`
	ManageSafeMembers       bool `json:"manageSafeMembers"`
	ViewSafeMembers         bool `json:"viewSafeMembers"`
	ViewAuditLog            bool `json:"viewAuditLog"`
	UseAccounts             bool `json:"useAccounts"`
	RetrieveAccounts        bool `json:"retrieveAccounts"`
	ListAccounts            bool `json:"listAccounts"`
	AddAccounts             bool `json:"addAccounts"`
	UpdateAccountContent    bool `json:"updateAccountContent"`
	UpdateAccountProperties bool `json:"updateAccountProperties"`
	RenameAccounts          bool `json:"renameAccounts"`
	DeleteAccounts          bool `json:"deleteAccounts"`
	UnlockAccounts          bool `json:"unlockAccounts"`
}

type credential struct {
	Safe         string         `json:"safeName"`
	User         string         `json:"userName"`
	Pass         string         `json:"secret"`
	Address      string         `json:"address"`
	Platform     string         `json:"platformId"`
	FriendlyName string         `json:"name"`
	Type         string         `json:"secretType"`
	Props        accountProps   `json:"platformAccountProperties"`
	Settings     accountSetting `json:"secretManagement"`
}

type accountProps struct {
	Port   string `json:"port"`
	DBName string `json:"database"`
}

type accountSetting struct {
	AutoMgm bool `json:"automaticManagementEnabled"`
}

type member struct {
	Member     string   `json:"memberName"`
	MemberType string   `json:"memberType"`
	SafePerm   safeperm `json:"permissions"`
}

type syncMember struct {
	Member     string   `json:"memberName"`
	MemberType string   `json:"memberType"`
	SafePerm   syncPerm `json:"permissions"`
}

type syncPerm struct {
	UseAccounts      bool `json:"useAccounts"`
	RetrieveAccounts bool `json:"retrieveAccounts"`
	ListAccounts     bool `json:"listAccounts"`
	Access           bool `json:"accessWithoutConfirmation"`
}

// GLOBAL VARIABLE DECLARES

var (
	// Convert this to manifest data
	strategy      = os.Getenv("AUTHN_STRATEGY")     //: api/k8s
	TOKEN         = os.Getenv("CONJUR_TOKEN_PATH")  //if authn_strategy->k8s
	baseConjurUri = os.Getenv("CONJUR_URL")         //cloud
	host          = os.Getenv("CONJUR_AUTHN_LOGIN") //if k8s, not needed
	api           = os.Getenv("CONJUR_AUTHN_KEY")   //-> Set to blank to avoid go error, but do not implement.
	safe          = os.Getenv("CONJUR_SAFE")
	pasQuery      = os.Getenv("CONJUR_PASQUERY")
	opcQuery      = os.Getenv("CONJUR_OPCQUERY")
	opkQuery      = os.Getenv("CONJUR_OPKQUERY")
	selfSigned    = os.Getenv("SELF_SIGNED")
	safePrefix    = os.Getenv("SAFE_PREFIX")
	basePASUri    = os.Getenv("PAS_URI")
	tenant        = os.Getenv("TENANT")
	onboardBranch = os.Getenv("CONJUR_HOST_BRANCH")
	P             = os.Getenv("SERVICE_PORT")
	
	// Defaults
	USER           = "default"
	PASS           = "default"
	gt             = "client_credentials"
	pResult        = false
	cResult        = false
	sign           = false
	ticket         = 1
	req            = fmt.Sprintf("%s%d", "CHG", ticket)
	membership     = false
	syncUser       = "Conjur Sync" //Sync user in pCloud
	syncMemberType = "User"        // Sync User to replicate to Conjur
	CA_FILE        = "/app/cloud.pem"
	port           = "443"

	// Unitialized variables -> initialized in discovery
	certData string
	certKey string
	pasUser string
	pasPassword string 
	account string

	// URLs
	discoverPath   = baseConjurUri + "/resources/" + account + "?kind=variable&search=" + safe + "/"
	retrievalPath  = baseConjurUri + "/secrets?variable_ids="
	accountPath    = baseConjurUri + "/info"
	
)

func httpClient(s bool) *http.Client {

	// Construct httpClient using caCert pool

	caCert, err := os.ReadFile(CA_FILE)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	c := &http.Client{

		Transport: &http.Transport{
			TLSHandshakeTimeout: 700 * time.Millisecond,
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: s,
			},
		},
	}
	
	return c

}

func handleIdentityAuthn(client *http.Client) string {

	authnUrl := "https://" + tenant + ".id.cyberark.cloud/oauth2/platformtoken"
	method := "POST"

	payload := strings.NewReader("client_id=" + url.QueryEscape(pasUser) + "&grant_type=" + gt + "&client_secret=" + pasPassword)

	req, err := http.NewRequest(method, authnUrl, payload)
	if err != nil {

		log.Fatal(err)

	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {

		log.Fatal(err)

	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Fatal(err)

	}

	if res.StatusCode == 200 {

		authzToken := token{}
		jsonError := json.Unmarshal(body, &authzToken)
		if jsonError != nil {

			log.Fatal(jsonError)

		}
		return string(authzToken.Access_token)

	} else {

		log.Println(string(body))
		log.Fatal("Failed to authenticate:", res.StatusCode)

	}

	log.Fatal("Unable to authenticate to ISPSS.")
	return "Failed."

}

func checkFile() bool {

	if _, err := os.Stat(TOKEN); err == nil {
		return true
	 } else {
		return false
	 }

}

func handleConjurAuthn(client *http.Client) string {

	// Host API Key authentication with Conjur
	// Refactor to use authn-k8s (jwt or cert)
	// Implement check on authn methods

	log.Printf("Using authentication strategy [%s]", strategy)

	if strategy == "k8s" {

		log.Println("Reading local authorization token.")

		for {

			status := checkFile()

			if status {

			token, err := os.ReadFile(TOKEN)

			if err != nil {

				log.Fatal(err)

			}

			log.Println("Encoding Token")

			data := enc.StdEncoding.EncodeToString([]byte(token))

			return string(data)

			} else {
				
				log.Println("Waiting for token to become available.")
				time.Sleep(5 * time.Second)

			}
		}

	} else if strategy == "api" {

		// Encoding host converting / to %2F
		encodedHost := url.QueryEscape(host)

		authnUrl := baseConjurUri + "/authn/" + account + "/" + encodedHost + "/authenticate"
		method := "POST"

		payload := strings.NewReader(api)

		req, err := http.NewRequest(method, authnUrl, payload)
		if err != nil {

			log.Fatal(err)

		}

		req.Header.Add("Accept-Encoding", "base64")
		req.Header.Add("Content-Type", "text/plain")

		res, err := client.Do(req)
		if err != nil {

			log.Fatal(err)

		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {

			log.Fatal(err)

		}

		if res.StatusCode == 200 {

			log.Println("Successfully authenticated as " + host + " to " + baseConjurUri)

			return string(body)

		} else {

			log.Fatal("Failed to authenticate:", res.StatusCode)

		}
	}

	log.Fatal("No strategy declared, check your configuration and rerun the application.")
	return "Failed."

}

func discover(t string, client *http.Client, query string) string {

	var sb strings.Builder

	authnUrl := discoverPath + query
	method := "GET"
	req, err := http.NewRequest(method, authnUrl, nil)

	if err != nil {

		log.Println(err)
		return "false"

	}
	tokenHeader := "Token token=\"" + t + "\""
	req.Header.Add("Authorization", tokenHeader)

	res, err := client.Do(req)
	if err != nil {

		log.Println(err)
		return "false"

	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Println(err)
		return "false"

	}

	secretPaths := []secret{}
	jsonErr := json.Unmarshal(body, &secretPaths)
	if jsonErr != nil {

		log.Fatal(jsonErr)

	}

	log.Printf("Successfully found secrets, preparing paths for [%s]", query)

	for _, values := range secretPaths {

		sb.WriteString(values.Path + ",")

	}

	log.Println("Converting buffer to string.")
	dirtyVariables := sb.String()
	log.Println("Cleaning variables.")
	cleanVariables := strings.TrimSuffix(dirtyVariables, ",")

	return cleanVariables

}

func initSecrets(t string, client *http.Client, paths string) [2]string {

	authnUrl := retrievalPath + paths
	method := "GET"
	req, err := http.NewRequest(method, authnUrl, nil)

	if err != nil {

		log.Fatal(err)

	}
	tokenHeader := "Token token=\"" + t + "\""
	req.Header.Add("Authorization", tokenHeader)

	res, err := client.Do(req)
	if err != nil {

		log.Fatal(err)

	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Fatal(err)

	}

	responseDecoded := make(map[string]string)

	err = json.NewDecoder(bytes.NewBuffer(body)).Decode(&responseDecoded)
	if err != nil {
		log.Fatal("Error coding JSON response.")
	}

	for k, v := range responseDecoded {

		lastIndex := strings.LastIndex(k, "/")

		attrChk := k[lastIndex+1:]

		if attrChk == "username" {
			USER = v
		}
		if attrChk == "password" {
			PASS = v
		}
		
	}

	var payload [2]string
	/*
	*	Working with discovery I build a mapped array as follows:
	*	payload[1] := USER
	*	payload[2] := PASS
	*
	* 	This is an example of implementing discovery and can be retrofit for any need.
	 */

	payload[0] = USER
	payload[1] = PASS

	return payload
}

func setConjurData(client *http.Client) {

	log.Printf("Authenticating to [%s]", baseConjurUri)

	token := handleConjurAuthn(client)

	log.Printf("Discovering required secrets from [%s]", safe)

	pasSecretPaths := discover(token, client, pasQuery)
	certPath := discover(token, client, opcQuery)
	keyPath := discover(token, client, opkQuery)

	log.Printf("Found secrets, retrieving values.")

	pasSecrets := initSecrets(token, client, pasSecretPaths)
	certSecrets := initSecrets(token, client, certPath)
	keySecrets := initSecrets(token, client, keyPath)

	pasUser = pasSecrets[0]
	pasPassword = pasSecrets[1]
	certData = certSecrets[1]
	certKey = keySecrets[1]

}

func addSync(client *http.Client, token string, safe string, ticket string) bool {

	safesUrl := basePASUri + "/Safes/" + safe + "/Members/"
	method := "POST"

	// ACL SYNC
	syncPermBlock := syncPerm{
		UseAccounts:      true,
		RetrieveAccounts: true,
		ListAccounts:     true,
		Access:           true,
	}

	syncUser := syncMember{
		Member:     syncUser,
		MemberType: syncMemberType,
		SafePerm:   syncPermBlock,
	}

	thisDat, err := json.Marshal(syncUser)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(method, safesUrl, bytes.NewBuffer(thisDat))
	if err != nil {

		log.Fatal(err)

	}

	tokenHeader := "Bearer " + token
	req.Header.Add("Authorization", tokenHeader)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {

		log.Fatal(err)

	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Fatal(err)

	}

	if res.StatusCode == 201 || res.StatusCode == 200 {

		return true

	} else {

		log.Printf("[%s] Error onboarding Synchronizer user code:%d", ticket, res.StatusCode)
		log.Printf("[%s] %s", ticket, string(body))
		return false

	}

}

func updateMembers(client *http.Client, token string, safe string, group string, ticket string) bool {

	safesUrl := basePASUri + "/Safes/" + safe + "/Members/"
	method := "POST"

	// ACL USER
	permissionBlock := safeperm{
		ManageSafe:              true,
		ManageSafeMembers:       true,
		ViewSafeMembers:         true,
		ViewAuditLog:            true,
		UseAccounts:             true,
		RetrieveAccounts:        true,
		ListAccounts:            true,
		AddAccounts:             true,
		UpdateAccountContent:    true,
		UpdateAccountProperties: true,
		RenameAccounts:          true,
		DeleteAccounts:          true,
		UnlockAccounts:          true,
	}

	thisUser := member{
		Member:     group,
		MemberType: syncMemberType,
		SafePerm:   permissionBlock,
	}

	thisDat, err := json.Marshal(thisUser)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("[%s] %s", ticket, string(thisDat))

	req, err := http.NewRequest(method, safesUrl, bytes.NewBuffer(thisDat))
	if err != nil {

		log.Fatal(err)

	}

	tokenHeader := "Bearer " + token
	req.Header.Add("Authorization", tokenHeader)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {

		log.Fatal(err)

	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Fatal(err)

	}

	if res.StatusCode == 201 || res.StatusCode == 200 {

		syncResult := addSync(client, token, safe, ticket)

		if syncResult {
			log.Printf("[%s] Onboarded Synchronizer.", ticket)
			return true

		} else {
			log.Printf("[%s] Error onboarding Synchronizer.", ticket)
			return false
		}

	} else {

		log.Printf("[%s] Error onboarding membership code:%d", ticket, res.StatusCode)
		log.Printf("[%s] %s", ticket, string(body))
		return false

	}

}

func onboardSafe(client *http.Client, token string, safe string, ticket string, group string) bool {

	safesUrl := basePASUri + "/Safes"
	method := "POST"

	s := safeObject{
		Safe:      safe,
		Desc:      ticket,
		Retention: 0,
	}

	payload, err := json.Marshal(s)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(method, safesUrl, bytes.NewBuffer(payload))
	if err != nil {

		log.Fatal(err)

	}

	tokenHeader := "Bearer " + token
	req.Header.Add("Authorization", tokenHeader)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {

		log.Fatal(err)

	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Fatal(err)

	}

	log.Printf("[%s] %s" , ticket, string(body))

	membership = updateMembers(client, token, safe, group, ticket)

	if membership {

		log.Printf("[%s] Onboarded safe and updated group membership.", ticket)
		return true

	} else {

		log.Printf("[%s] Unable to update group membership.", ticket)
		return false

	}

}

func onboardCreds(client *http.Client, token string, pasObj [9]string, ticket string) bool {

	safesUrl := basePASUri + "/Accounts/"
	method := "POST"

	props := accountProps{
		DBName: pasObj[7],
		Port:   pasObj[6],
	}

	settings := accountSetting{
		AutoMgm: true,
	}

	accountObject := credential{
		FriendlyName: pasObj[5],
		Address:      pasObj[4],
		User:         pasObj[1],
		Pass:         pasObj[3],
		Safe:         pasObj[0],
		Platform:     pasObj[8],
		Type:         "password",
		Props:        props,
		Settings:     settings,
	}

	payload, err := json.Marshal(accountObject)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(method, safesUrl, bytes.NewBuffer(payload))
	if err != nil {

		log.Fatal(err)

	}

	tokenHeader := "Bearer " + token
	req.Header.Add("Authorization", tokenHeader)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {

		log.Fatal(err)

	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Fatal(err)

	}

	if res.StatusCode == 201 || res.StatusCode == 200 {

		log.Printf("[%s] Successfully onboarded credentials into %s", ticket, pasObj[0])
		return true

	} else {

		log.Printf("[%s] Unable to add credentials to safe %d", ticket, res.StatusCode)
		log.Println(string(body))
		return false

	}

}

func delSafe(client *http.Client, token string, safe string, ticket string) {

	safesUrl := basePASUri + "/Safes/" + safe
	method := "DELETE"

	req, err := http.NewRequest(method, safesUrl, nil)
	if err != nil {

		log.Fatal(err)

	}

	tokenHeader := "Bearer " + token
	req.Header.Add("Authorization", tokenHeader)
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {

		log.Fatal(err)

	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Fatal(err)

	}

	if res.StatusCode == 204 {

		log.Printf("[%s] Successfully deleted %s", ticket, safe)

	} else {

		log.Printf("[%s] Failed to delete %s", ticket, safe)
		log.Println(string(body))

	}

}

func check(v string) bool {
	if v == "" {

		return false

	} else {

		return true

	}
}

func getTicket() string {

	if ticket == 1 {
		ticket++
		return req
	} else {
		ticket++
		req = fmt.Sprintf("%s%d", "CHG", ticket)
		return req
	}

}

func validateSafe(client *http.Client, token string, safe string, ticket string) bool {

	var sb strings.Builder

	url := baseConjurUri + "/resources/" + account + "?kind=group&search=" + safe + "/delegation/consumers&limit=1"
	method := "GET"
	req, err := http.NewRequest(method, url, nil)

	if err != nil {

		log.Println(err)
		return false

	}
	tokenHeader := "Token token=\"" + token + "\""
	req.Header.Add("Authorization", tokenHeader)

	res, err := client.Do(req)
	if err != nil {

		log.Println(err)
		return false

	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Println(err)
		return false

	}

	safePath := []secret{}
	jsonErr := json.Unmarshal(body, &safePath)
	if jsonErr != nil {

		log.Fatal(jsonErr)

	}

	log.Printf("[%s] Sending request [%s]", ticket, url)

	for _, values := range safePath {

		sb.WriteString(values.Path)

	}

	safeStr := safe + "/delegation/consumers"
	safeCheck := strings.ContainsAny(safeStr, string(sb.String()))

	return safeCheck
}

func entitleConjurHost(client *http.Client, token string, namespace string, serviceaccount string, safe string, ticket string) bool {

	url := baseConjurUri + "/policies/" + account + "/policy/data/vault/" + safe + "/delegation"
	method := "POST"

	payload :=
		`
# loaded into data/vault/` + safe + `/delegation
- !grant
  role: !group consumers
  member: !host /` + onboardBranch + `/system:serviceaccount:` + namespace + `:` + serviceaccount

	req, err := http.NewRequest(method, url, strings.NewReader(payload))

	if err != nil {

		log.Println(err)
		return false

	}
	tokenHeader := "Token token=\"" + token + "\""
	req.Header.Add("Authorization", tokenHeader)

	res, err := client.Do(req)
	if err != nil {

		log.Println(err)
		return false

	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Println(err)
		return false

	}

	entitled := false

	if res.StatusCode == 201 {

		entitled = true
		log.Printf("[%s] Successfully entitled host to %s [%d]", ticket, safe, res.StatusCode)
		log.Printf("[%s] %s", ticket, string(body))
		return entitled

	} else {

		log.Printf("[%s] Failed entitled host to %s [%d]", ticket, safe, res.StatusCode)
		log.Printf("[%s] %s", ticket, string(body))
		return entitled

	}

}

func onboardConjurHost(client *http.Client, token string, namespace string, serviceaccount string, cluster string, ticket string) bool {

	url := baseConjurUri + "/policies/" + account + "/policy/" + onboardBranch
	method := "POST"

	ts := time.Now().Format("01-02-2006 15:04:05 Monday")

	payload :=
		`
- !host
  id: system:serviceaccount:` + namespace + `:` + serviceaccount + `
  annotations:
    authn-jwt/` + cluster + `/kubernetes.io/namespace: ` + namespace + `
    authn-jwt/` + cluster + `/kubernetes.io/serviceaccount/name: ` + serviceaccount + `
    authn/api-key: true
    ticket_number: ` + ticket + `
    automation_creation_time: ` + ts + `

- !grant
  role: !group authenticators
  member: !host system:serviceaccount:` + namespace + `:` + serviceaccount

	req, err := http.NewRequest(method, url, strings.NewReader(payload))

	if err != nil {

		log.Println(err)
		return false

	}
	tokenHeader := "Token token=\"" + token + "\""
	req.Header.Add("Authorization", tokenHeader)

	res, err := client.Do(req)
	if err != nil {

		log.Println(err)
		return false

	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {

		log.Println(err)
		return false

	}

	onboarded := false

	if res.StatusCode == 201 {

		onboarded = true
		log.Printf("[%s] Successfully onboarded host to Conjur [%d]", ticket, res.StatusCode)
		return onboarded

	} else {

		log.Printf("[%s] Failed to onboard host to Conjur [%d]", ticket, res.StatusCode)
		log.Printf("[%s] %s", ticket, string(body))
		return onboarded

	}

}

// HTTP HANDLERS
func landingHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "", http.StatusUnauthorized)
}

func ticketLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ticket" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "/app/ticket.html")
	default:
		http.Error(w, "", http.StatusUnauthorized)
	}
}

func onboardingHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/onboard" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "POST":
		if err := r.ParseForm(); err != nil {
			log.Printf("ParseForm() err: %v", err)
			return
		}

			requestID := getTicket()
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Processing Request ID: " + requestID + "\n"))
			log.Printf("[%s] Started Processing", requestID)

			objSafeName := safePrefix + strings.ToUpper(r.FormValue("appid"))
			objUserName := r.FormValue("user")
			objGroupName := r.FormValue("acl")
			objUserPass := r.FormValue("pass")
			objAddress := r.FormValue("address")
			objFName := r.FormValue("name")
			objPort := r.FormValue("port")
			objDBName := r.FormValue("dbname")
			objPFName := r.FormValue("platform")

			objConjNS := r.FormValue("ns")
			objConjSA := r.FormValue("sa")
			objConjCluster := r.FormValue("cluster")

			var pasOnboardObj [9]string

			pasOnboardObj[0] = objSafeName
			pasOnboardObj[1] = objUserName
			pasOnboardObj[2] = objGroupName
			pasOnboardObj[3] = objUserPass
			pasOnboardObj[4] = objAddress
			pasOnboardObj[5] = objFName
			pasOnboardObj[6] = objPort
			pasOnboardObj[7] = objDBName
			pasOnboardObj[8] = objPFName

			for p := 0; p < len(pasOnboardObj); p++ {

				pResult = check(pasOnboardObj[p])
				if !pResult {
					w.Write([]byte("Failed validating Safe Onboarding information form data. Please resubmit your data.\n"))
					log.Printf("[%s] Failed to validate %s", requestID, pasOnboardObj[p])
					pResult = false
					break
				}

			}

			var conjOnboardObj [3]string

			conjOnboardObj[0] = objConjNS
			conjOnboardObj[1] = objConjSA
			conjOnboardObj[2] = objConjCluster

			for c := 0; c < len(conjOnboardObj); c++ {

				cResult = check(conjOnboardObj[c])
				if !cResult {
					w.Write([]byte("Failed validating Conjur Identity information in the form data. Please resubmit your data.\n"))
					log.Printf("[%s] Failed to validate %s", requestID, conjOnboardObj[c])
					cResult = false
					break
				}

			}

			if pResult && cResult {

				w.Write([]byte("Validated attributes...\n"))
				log.Printf("[%s] Validated attributes.", requestID)

				// Set up http Client
				hClient := httpClient(sign)
				sessionAuth := handleIdentityAuthn(hClient)

				w.Write([]byte("Onboarding safe " + objSafeName + "\n"))
				log.Printf("[%s] Attempting to onboard %s", requestID, objSafeName)

				safeResult := onboardSafe(hClient, sessionAuth, objSafeName, requestID, objGroupName)

				if safeResult {

					w.Write([]byte("Onboarded safe " + objSafeName + "\n"))
					log.Printf("[%s] Onboarded %s", requestID, objSafeName)
					w.Write([]byte("Adding credentials to " + objSafeName + "\n"))
					log.Printf("[%s] Adding credentials to %s", requestID, objSafeName)

					credResult := onboardCreds(hClient, sessionAuth, pasOnboardObj, requestID)

					if credResult {

						w.Write([]byte("Onboarded credentials into " + objSafeName + "\n"))
						log.Printf("[%s] Onboarded credentials into %s", requestID, objSafeName)
						w.Write([]byte("Checking Conjur safe replication..." + "\n"))
						log.Printf("[%s] Checking Conjur Safe Replication.", requestID)

						safeExist := false

						token := handleConjurAuthn(hClient)

						for i := 1; i < 12; i++  {

							token := handleConjurAuthn(hClient)

							safeExist = validateSafe(hClient, token, objSafeName, requestID)

							if safeExist {
								log.Printf("[%s] Found Conjur Safe", requestID)
								w.Write([]byte("Found Conjur Safe" + "\n"))
								break
							}

							log.Printf("[%s] Safe not found, waiting for replication.. sleeping for 10 seconds..", requestID)
							// Wait 10 seconds to avoid spamming logs.
							time.Sleep(10 * time.Second)

						}

						w.Write([]byte("Attempting to create identity\n"))
						log.Printf("[%s] Attempting to create identity", requestID)

						hostOnboard := onboardConjurHost(hClient, token, objConjNS, objConjSA, objConjCluster, requestID)

						if hostOnboard {

							w.Write([]byte("Successfully created identity\n"))
							log.Printf("[%s] Successfully created identity", requestID)

							entitle := entitleConjurHost(hClient, token, objConjNS, objConjSA, objSafeName, requestID)

							if entitle {

								w.Write([]byte("Successfully entitled identity\n"))
								log.Printf("[%s] Successfully entitled identity.", requestID)

							} else {

								w.Write([]byte("Failed to entitle identity\n"))
								log.Printf("[%s] Failed to entitle identity", requestID)

							}

						} else {

							w.Write([]byte("Failed to create identity\n"))
							log.Printf("[%s] Failed to create identity", requestID)

						}

					}

				} else {

					w.Write([]byte("Failed adding credentials to " + objSafeName + "\nPlease check the logs and try again.\n"))

				}

			}

	default:
		http.Error(w, "", http.StatusUnauthorized)
	}

}

func deleteLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/delete" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}


	switch r.Method {
	case "POST":
		if err := r.ParseForm(); err != nil {
			log.Printf("ParseForm() err: %v", err)
			return
		}

		objSafeName := safePrefix + strings.ToUpper(r.FormValue("safe"))

		// Set up http Client
		hClient := httpClient(sign)
		sessionAuth := handleIdentityAuthn(hClient)

		requestID := getTicket()

		log.Printf("[%s] Deleting %s ", requestID, objSafeName)

		delSafe(hClient, sessionAuth, objSafeName, requestID)

	default:
		http.Error(w, "", http.StatusUnauthorized)
	}

}

func queryLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/query" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case "POST":
		if err := r.ParseForm(); err != nil {
			log.Printf("ParseForm() err: %v", err)
			return
		}

		requestID := getTicket()

		objSafeName := safePrefix + strings.ToUpper(r.FormValue("safe"))

		// Set up http Client
		hClient := httpClient(sign)
		sessionAuth := handleConjurAuthn(hClient)
		log.Printf("[%s] Checking %s ", requestID, objSafeName)

		validateSafe(hClient, sessionAuth, objSafeName, requestID)

	default:
		http.Error(w, "", http.StatusUnauthorized)
	}

}

func hcLanding(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "", http.StatusUnauthorized)
	}

}

func serviceInit() {

	// Initialize API endpoints

	http.HandleFunc("/", landingHandler)
	http.HandleFunc("/onboard", onboardingHandler)
	http.HandleFunc("/ticket", ticketLanding)
	http.HandleFunc("/delete", deleteLanding)
	http.HandleFunc("/query", queryLanding)
	http.HandleFunc("/ping", hcLanding)

	go func () {

		log.Println("Health check active on 8080")
		hcErr := http.ListenAndServe(":8080", http.HandlerFunc( func (w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
			
		}))
		
		log.Fatal(hcErr)

	}()
	
	
	err := http.ListenAndServeTLS(":"+port, "cert", "key", nil)
	log.Fatal(err)
	log.Printf("Successfully listening on %s.. Awaiting requests..", port)

}

func deployCerts(c string, k string) {
	certFile := []byte(c)
	err := os.WriteFile("cert", certFile, 0400)
	if err != nil {
		panic(err)
	}

	keyFile := []byte(k)
	kerr := os.WriteFile("key", keyFile, 0400)
	if err != nil {
		panic(kerr)
	}
}

func checkConf(){

	version, err := os.ReadFile("/app/ver")

	if err != nil {

		log.Fatal(err)

	}
	
	log.Printf("JWT Policy Automation Version %s", string(version))

	log.Println("Validating environment variables.")

	if strategy == "" {
		log.Fatal("Strategy not populated. Check your configuration and redeploy.")
	} else if strategy == "k8s" {

		// If using k8s initialize variables empty and check for proper values
		host = ""
		api = ""
		if TOKEN == "" {
			log.Fatal("Token Path not populated. Check your configuration and redeploy.")
		}

	} else if strategy == "api" {

		// If using API Key, initialize variables empty and check for proper values
		TOKEN = ""

		if host == "" {
			log.Fatal("Host not populated. Check your configuration and redeploy.")
		}
		if api == "" {
			log.Fatal("API Key not populated. Check your configuration and redeploy.")
		}

	}

	if P == "" {

		log.Println("Port not declared, defaulting to 443.")
		
	} else {

		port = P

	}

	if baseConjurUri == "" {
		log.Fatal("Conjur URL not populated. Check your configuration and redeploy.")
	}
	if safe == "" {
		log.Fatal("Safe not populated. Check your configuration and redeploy.")
	}
	if pasQuery == "" {
		log.Fatal("PAS Query not populated. Check your configuration and redeploy.")
	}
	if opcQuery == "" {
		log.Fatal("Public Cert (OPC) Query not populated. Check your configuration and redeploy.")
	}
	if opkQuery == "" {
		log.Fatal("Private Key (OPK) Query not populated. Check your configuration and redeploy.")
	}
	if safePrefix == "" {
		log.Fatal("Safe Prefix not populated. Check your configuration and redeploy.")
	}
	if CA_FILE == "" {
		log.Fatal("Cert Authority data not populated. Check your configuration and redeploy.")
	}
	if basePASUri == "" {
		log.Fatal("Base PAS URL data not populated. Check your configuration and redeploy.")
	}
	if tenant == "" {
		log.Fatal("Shared Services tenant not populated. Check your configuration and redeploy.")
	}
	if onboardBranch == "" {
		log.Fatal("Conjur Host path not populated. Check your configuration and redeploy.")
	}
	if selfSigned == "true" {

		log.Println("Self signed certificates configured.")
		sign = true

	}

	log.Println("Done validating variables.")

}

func setAccount(client *http.Client) {

	//var sb strings.Builder
	method := "GET"
	req, err := http.NewRequest(method, accountPath, nil)
	if err != nil {

		log.Println(err)

	}

	res, err := client.Do(req)
	if err != nil {

		log.Println(err)

	}
	defer res.Body.Close()

	if res.StatusCode == 401 {

		log.Println("Configured for Conjur Cloud.")
		account = "conjur"

	} else {

		body, err := io.ReadAll(res.Body)
		if err != nil {

			log.Println(err)

		}

		var thisAccount config
		jsonErr := json.Unmarshal(body, &thisAccount)
		if jsonErr != nil {

				log.Fatal(jsonErr)

		}

		log.Printf("Found Account %s", string(thisAccount.Configuration.Conjur.Account))

		account = thisAccount.Configuration.Conjur.Account

	}

}

func main() {

	checkConf()

	log.Println("Starting up...")

	// Set up http Client
	hClient := httpClient(sign)

	setAccount(hClient)
	setConjurData(hClient)

	log.Println("Successfully set up services.")

	log.Println("Setting up local certificates.")
	deployCerts(certData, certKey)

	log.Println("Starting Web Services..")
	serviceInit()

}
