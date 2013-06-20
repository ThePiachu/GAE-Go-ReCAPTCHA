//Google App Engine Go ReCAPTCHA
//Based on go-recaptcha code by dpapathanasiou
//https://github.com/dpapathanasiou/go-recaptcha/
//Copyright ThePiachu, 2013

package ReCaptcha

import (
	"appengine"
	"appengine/urlfetch"
	"net/url"
	"strings"
	"io/ioutil"
	"net/http"
)

var ReCaptchaSever string = "http://www.google.com/recaptcha/api/verify"
var ReCaptchaPrivateKey string

//Call this function first to specify your private key
func SetupReCaptcha(privateKey string){
	ReCaptchaPrivateKey=privateKey;
}

//This function contacts the ReCaptcha server and verifies if the response is correct
func checkReCaptcha(c appengine.Context, remoteip, challenge, response string) (string) {
	client := urlfetch.Client(c)
	resp, err := client.PostForm(ReCaptchaSever, url.Values{"privatekey": {ReCaptchaPrivateKey}, "remoteip": {remoteip}, "challenge": {challenge}, "response": {response}})
	var answer string
	if err != nil {
		c.Errorf("ReCaptcha post error: %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Errorf("ReCaptcha read error: could not read body: %s", err)
	} else {
		answer = string(body)
	}
	return answer
}

//Call this function to verify your ReCAPTCHA by specifying all the parameters
func Confirm(c appengine.Context, remoteip, challenge, response string) (bool) {
	return strings.HasPrefix(checkReCaptcha(c, remoteip, challenge, response), "true")
}

//Call this function to verify your ReCAPTCHA hussle-free
func ConfirmRequest(r *http.Request) (bool){
	challenge, challengeFound := r.Form["recaptcha_challenge_field"]
	recaptchaResp, respFound := r.Form["recaptcha_response_field"]
	
	if challengeFound && respFound {
		c:=appengine.NewContext(r)
		return Confirm(c, strings.Split(r.RemoteAddr,":")[0] , challenge[0], recaptchaResp[0])
	}
	return false;
}