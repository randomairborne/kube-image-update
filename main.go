package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/go-chi/chi/v5"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Deployment struct {
	namespace string
	name      string
}

type State struct {
	kube   *kubernetes.Clientset
	tokens map[Deployment][]byte
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
	authSecret, err := kubeClient.CoreV1().Secrets(secretNamespace).Get(context.Background(), "kube-restart-tokens", metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}
	tokens := make(map[Deployment][]byte, len(authSecret.Data))
	for key, token := range authSecret.Data {
		split := strings.Split(key, ".")
		if len(split) != 2 {
			panic(fmt.Sprintf("key %s could not be split into a namespace and name at .", key))
		}
		namespace, name := split[0], split[1]
		deployment := Deployment{
			namespace: namespace,
			name:      name,
		}
		tokens[deployment] = token

	}
	state := State{
		kube:   kubeClient,
		tokens: tokens,
	}
	mux := chi.NewMux()
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
	deploymentNamespace := r.Context().Value("namespace").(string)
	deploymentName := r.Context().Value("deployment").(string)
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

	authzd := checkMac(body, authSig, state.tokens[deployment])
	if !authzd {
		w.WriteHeader(401)
		return
	}

	err = state.RestartDeployment(r.Context(), deploymentNamespace, deploymentName)
	if err != nil {
		w.WriteHeader(500)
		log.Println(err.Error())
	} else {
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