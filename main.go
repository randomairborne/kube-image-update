package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var SecretName string = "kube-restart-tokens"

type Deployment struct {
	namespace string
	name      string
}

type Unit struct{}

type State struct {
	kube         *kubernetes.Clientset
	namespace    string
	waitForToken <-chan map[Deployment][]byte
	updateToken  chan<- map[Deployment][]byte
	requestToken chan<- Unit
}

func (s *State) GetTokens() map[Deployment][]byte {
	s.requestToken <- Unit{}
	return <-s.waitForToken
}

func (s *State) SetTokens(tokens map[Deployment][]byte) {
	s.updateToken <- tokens
}

func NewState(cs *kubernetes.Clientset, namespace string) State {
	reqs := make(chan Unit)
	resps := make(chan map[Deployment][]byte)
	mutates := make(chan map[Deployment][]byte)
	go service(reqs, resps, mutates)
	return State{
		kube:         cs,
		namespace:    namespace,
		waitForToken: resps,
		updateToken:  mutates,
		requestToken: reqs,
	}
}

func service(req <-chan Unit, resp chan<- map[Deployment][]byte, mutate <-chan map[Deployment][]byte) {
	data := make(map[Deployment][]byte)
	for {
		select {
		case <-req:
			resp <- data
		case data = <-mutate:
		}
	}
}

func (s *State) updateSecrets() {
	var hundred_years int64 = 86400 * 365 * 100
	sendInitials := false
	opts := metav1.ListOptions{
		FieldSelector:        fields.OneTermEqualSelector("metadata.name", SecretName).String(),
		TimeoutSeconds:       &hundred_years,
		Watch:                true,
		SendInitialEvents:    &sendInitials,
		ResourceVersionMatch: "NotOlderThan",
	}
	fmt.Printf("starting to watch %s/secrets/%s\n", s.namespace, SecretName)
	auth, err := s.kube.CoreV1().Secrets(s.namespace).Watch(context.Background(), opts)
	if err != nil {
		panic(fmt.Sprintf("Error getting secrets: `%s` (do you have the watch verb for secrets?)", err.Error()))
	}
	rc := auth.ResultChan()
	for {
		event := <-rc
		secret := event.Object.(*v1.Secret)
		fmt.Println("Got new secret to watch")
		tokens := secretToTokens(*secret)
		s.SetTokens(tokens)
	}
}

func main() {
	secretNamespace := os.Getenv("TOKEN_SECRET_NAMESPACE")
	if secretNamespace == "" {
		secretNamespace = "default"
	}
	icc, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	kubeClient := kubernetes.NewForConfigOrDie(icc)

	state := NewState(kubeClient, secretNamespace)

	go state.updateSecrets()

	mux := chi.NewRouter()
	mux.Post("/restart/{namespace}/{deployment}", func(w http.ResponseWriter, r *http.Request) {
		state.HandleHttp(w, r)
	})
	mux.Get("/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	log.Println("Starting HTTP server on 0.0.0.0:8080")
	log.Fatal(srv.ListenAndServe())
}

func (state *State) HandleHttp(w http.ResponseWriter, r *http.Request) {
	deploymentNamespace := chi.URLParam(r, "namespace")
	deploymentName := chi.URLParam(r, "deployment")
	deployment := Deployment{
		namespace: deploymentNamespace,
		name:      deploymentName,
	}
	authHeader := r.Header.Get("X-Hub-Signature-256")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(400)
		return
	}

	trimmedAuthHex, _ := strings.CutPrefix(authHeader, "sha256=")
	authSig, err := hex.DecodeString(trimmedAuthHex)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(400)
		return
	}

	token, exists := state.GetTokens()[deployment]
	if !exists {
		log.Printf("Could not find deployment %s.%s", deployment.namespace, deployment.name)
		w.WriteHeader(404)
		return
	}

	authzd := checkMac(body, authSig, token)
	if !authzd {
		log.Println("Failed to validate MAC")
		w.WriteHeader(401)
		return
	}

	err = state.RestartDeployment(r.Context(), deploymentNamespace, deploymentName)
	if err != nil {
		log.Println(err.Error())
		w.WriteHeader(500)
	} else {
		log.Printf("Restarted deployment %s.%s", deployment.namespace, deployment.name)
		w.WriteHeader(204)
	}
}

func (state *State) RestartDeployment(ctx context.Context, namespace string, deployName string) error {
	deployment, err := state.kube.AppsV1().Deployments(namespace).Get(ctx, deployName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if deployment.Spec.Template.ObjectMeta.Annotations == nil {
		deployment.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
	}
	deployment.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)

	_, err = state.kube.AppsV1().Deployments(namespace).Update(ctx, deployment, metav1.UpdateOptions{})
	return err
}

func checkMac(payload []byte, payloadMAC []byte, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(payloadMAC, expectedMAC)
}

func secretToTokens(secret v1.Secret) map[Deployment][]byte {
	tokens := make(map[Deployment][]byte, len(secret.Data))
	for key, token := range secret.Data {
		split := strings.Split(key, ".")
		if len(split) != 2 {
			panic(fmt.Sprintf("key %s could not be split into a namespace and name at .", key))
		}
		deploymentNamespace, deploymentName := split[0], split[1]
		deployment := Deployment{
			namespace: deploymentNamespace,
			name:      deploymentName,
		}
		tokens[deployment] = token
		log.Printf("got namespace %s and deployment %s", deploymentNamespace, deploymentName)
	}
	return tokens
}
