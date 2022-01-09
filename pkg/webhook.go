package pkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"strings"

	admissionV1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog"
)

var (
	runtimeScheme = runtime.NewScheme()
	codeFactory   = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codeFactory.UniversalDeserializer()
)

type WhSvrParam struct {
	Port     int
	CertFile string
	KeyFile  string
}

type WebhookServer struct {
	Server              *http.Server
	WhiteListRegistries []string // 白名单的镜像仓库列表
}

func (s *WebhookServer) Handler(writer http.ResponseWriter, request *http.Request) {
	var body []byte
	if request.Body != nil {
		if data, err := ioutil.ReadAll(request.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		klog.Error("empty data body")
		http.Error(writer, "empty data body", http.StatusBadRequest)
		return
	}

	// 校验content-type
	contentType := request.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Error("Content-Type is %s, but expect application/json", contentType)
		klog.Error(writer, "Content-Type invalid, expect application/json", http.StatusBadRequest)
		return
	}

	// 数据序列化(validate、mutate)请求的数据都是AdmissionReview
	var admissionResponse *admissionV1.AdmissionResponse
	requestedAdmissionReview := admissionV1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &requestedAdmissionReview); err != nil {
		klog.Error("Can't decode body: %v", err)
		admissionResponse = &admissionV1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
				Code:    http.StatusInternalServerError,
			},
		}
	} else {
		//序列化成功，也就是说获取到了请求的AdmissionReview的数据
		if request.URL.Path == "/mutate" {
			// TODO
		} else if request.URL.Path == "/validate" {
			admissionResponse = s.validate(&requestedAdmissionReview)
		}
	}

	// 构造返回的 AdmissionReview这个结构体
	responseAdmissionReview := admissionV1.AdmissionReview{}
	// admission/v1
	responseAdmissionReview.APIVersion = requestedAdmissionReview.APIVersion // v1版本需要指定版本
	responseAdmissionReview.Kind = requestedAdmissionReview.Kind
	if admissionResponse != nil {
		responseAdmissionReview.Response = admissionResponse
		if requestedAdmissionReview.Request != nil {
			//返回的uuid需要和请求的uid保持一致
			responseAdmissionReview.Response.UID = requestedAdmissionReview.Request.UID
		}
	}

	klog.Info(fmt.Sprintf("sending response: %v", responseAdmissionReview.Response))
	// send response
	respBytes, err := json.Marshal(responseAdmissionReview)
	if err != nil {
		klog.Error("Can't encode response: %v", err)
		http.Error(writer, fmt.Sprintf("Can't encode response: %v", err), http.StatusBadRequest)
		return
	}
	klog.Info("Ready to write response...")

	if _, err := writer.Write(respBytes); err != nil {
		klog.Error("Can't write response: %v", err)
		http.Error(writer, fmt.Sprintf("Can't write response: %v", err), http.StatusBadRequest)
	}

}

func (s *WebhookServer) validate(ar *admissionV1.AdmissionReview) *admissionV1.AdmissionResponse {
	req := ar.Request
	var (
		allowed = true
		code = 200
		message = ""
	)
	klog.Info("AdmissionReview for Kind=%s, Namespace=%s, Name=%s, UID=%s",
		req.Kind.Kind, req.Namespace, req.Name, req.UID)
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		klog.Error("Can't unmarshal object raw: %v", err)
		allowed = false
		code = http.StatusBadRequest
		return &admissionV1.AdmissionResponse{
			Allowed: allowed,
			Result: &metav1.Status{
				Code: int32(code),
				Message: err.Error(),
			},
		}
	}

	// 处理真正的业务逻辑
	for _, container := range pod.Spec.Containers{
		var whitelisted = false
		for _, reg := range s.WhiteListRegistries {
			if strings.HasPrefix(container.Image, reg){
				whitelisted = true
			}
		}
		if !whitelisted {
			allowed = false
			code = http.StatusForbidden
			message = fmt.Sprintf("%s image comes from untrusted registry! Only images form %v are allowed.",
				container.Image, s.WhiteListRegistries)
			break
		}
	}
	return &admissionV1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Code: int32(code),
			Message: message,
		},
	}
}
