package main

import (
	"context"
	"fmt"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	vaultagentv1 "github.com/vault-agent/operator/api/v1"
)

// VaultAgentReconciler reconciles a VaultAgent object
type VaultAgentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=vault-agent.io,resources=vaultagents,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=vault-agent.io,resources=vaultagents/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=vault-agent.io,resources=vaultagents/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop
func (r *VaultAgentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the VaultAgent instance
	vaultAgent := &vaultagentv1.VaultAgent{}
	err := r.Get(ctx, req.NamespacedName, vaultAgent)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("VaultAgent resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get VaultAgent")
		return ctrl.Result{}, err
	}

	// Check if the deployment already exists, if not create a new one
	deployment := &appsv1.Deployment{}
	err = r.Get(ctx, req.NamespacedName, deployment)
	if err != nil && errors.IsNotFound(err) {
		// Define a new deployment
		dep := r.deploymentForVaultAgent(vaultAgent)
		logger.Info("Creating a new Deployment", "Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
		err = r.Create(ctx, dep)
		if err != nil {
			logger.Error(err, "Failed to create new Deployment", "Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
			return ctrl.Result{}, err
		}
		// Deployment created successfully - return and requeue
		return ctrl.Result{Requeue: true}, nil
	} else if err != nil {
		logger.Error(err, "Failed to get Deployment")
		return ctrl.Result{}, err
	}

	// Ensure the deployment size is the same as the spec
	size := vaultAgent.Spec.Replicas
	if *deployment.Spec.Replicas != size {
		deployment.Spec.Replicas = &size
		err = r.Update(ctx, deployment)
		if err != nil {
			logger.Error(err, "Failed to update Deployment", "Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
			return ctrl.Result{}, err
		}
		// Ask to requeue after 1 minute in order to give enough time for the
		// pods be created on the cluster side and the operand be able
		// to do the next update step accurately.
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	// Check if the service already exists, if not create a new one
	service := &corev1.Service{}
	err = r.Get(ctx, req.NamespacedName, service)
	if err != nil && errors.IsNotFound(err) {
		// Define a new service
		srv := r.serviceForVaultAgent(vaultAgent)
		logger.Info("Creating a new Service", "Service.Namespace", srv.Namespace, "Service.Name", srv.Name)
		err = r.Create(ctx, srv)
		if err != nil {
			logger.Error(err, "Failed to create new Service", "Service.Namespace", srv.Namespace, "Service.Name", srv.Name)
			return ctrl.Result{}, err
		}
	} else if err != nil {
		logger.Error(err, "Failed to get Service")
		return ctrl.Result{}, err
	}

	// Update the VaultAgent status with the pod names
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(vaultAgent.Namespace),
		client.MatchingLabels(labelsForVaultAgent(vaultAgent.Name)),
	}
	if err = r.List(ctx, podList, listOpts...); err != nil {
		logger.Error(err, "Failed to list pods", "VaultAgent.Namespace", vaultAgent.Namespace, "VaultAgent.Name", vaultAgent.Name)
		return ctrl.Result{}, err
	}

	// Update status
	vaultAgent.Status.Replicas = int32(len(podList.Items))
	readyReplicas := int32(0)
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning {
			readyReplicas++
		}
	}
	vaultAgent.Status.ReadyReplicas = readyReplicas

	// Determine phase
	if vaultAgent.Status.ReadyReplicas == 0 {
		vaultAgent.Status.Phase = "Pending"
	} else if vaultAgent.Status.ReadyReplicas == vaultAgent.Spec.Replicas {
		vaultAgent.Status.Phase = "Running"
	} else {
		vaultAgent.Status.Phase = "Pending"
	}

	err = r.Status().Update(ctx, vaultAgent)
	if err != nil {
		logger.Error(err, "Failed to update VaultAgent status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// deploymentForVaultAgent returns a VaultAgent Deployment object
func (r *VaultAgentReconciler) deploymentForVaultAgent(va *vaultagentv1.VaultAgent) *appsv1.Deployment {
	labels := labelsForVaultAgent(va.Name)
	replicas := va.Spec.Replicas

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      va.Name,
			Namespace: va.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{true}[0],
						RunAsUser:    &[]int64{65532}[0],
						RunAsGroup:   &[]int64{65532}[0],
						FSGroup:      &[]int64{65532}[0],
					},
					Containers: []corev1.Container{{
						Image: fmt.Sprintf("%s:%s", va.Spec.Image.Repository, va.Spec.Image.Tag),
						Name:  "vault-agent",
						Ports: []corev1.ContainerPort{{
							ContainerPort: 8200,
							Name:          "http",
						}},
						Env: []corev1.EnvVar{
							{
								Name:  "VAULT_AGENT_LOG_LEVEL",
								Value: va.Spec.Config.LogLevel,
							},
							{
								Name:  "VAULT_AGENT_BIND_ADDRESS",
								Value: "0.0.0.0:8200",
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    va.Spec.Resources.Requests.CPU,
								corev1.ResourceMemory: va.Spec.Resources.Requests.Memory,
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    va.Spec.Resources.Limits.CPU,
								corev1.ResourceMemory: va.Spec.Resources.Limits.Memory,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &[]bool{false}[0],
							ReadOnlyRootFilesystem:   &[]bool{true}[0],
							RunAsNonRoot:             &[]bool{true}[0],
							RunAsUser:                &[]int64{65532}[0],
							RunAsGroup:               &[]int64{65532}[0],
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/health",
									Port: intstr.FromString("http"),
								},
							},
							InitialDelaySeconds: 30,
							PeriodSeconds:       30,
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/ready",
									Port: intstr.FromString("http"),
								},
							},
							InitialDelaySeconds: 5,
							PeriodSeconds:       10,
						},
					}},
				},
			},
		},
	}

	// Set VaultAgent instance as the owner and controller
	controllerutil.SetControllerReference(va, dep, r.Scheme)
	return dep
}

// serviceForVaultAgent returns a VaultAgent Service object
func (r *VaultAgentReconciler) serviceForVaultAgent(va *vaultagentv1.VaultAgent) *corev1.Service {
	labels := labelsForVaultAgent(va.Name)

	srv := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      va.Name,
			Namespace: va.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{{
				Port:       8200,
				TargetPort: intstr.FromString("http"),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}

	// Set VaultAgent instance as the owner and controller
	controllerutil.SetControllerReference(va, srv, r.Scheme)
	return srv
}

// labelsForVaultAgent returns the labels for selecting the resources
// belonging to the given VaultAgent CR name.
func labelsForVaultAgent(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":     "vault-agent",
		"app.kubernetes.io/instance": name,
		"app.kubernetes.io/part-of":  "vault-agent-operator",
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultAgentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vaultagentv1.VaultAgent{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Complete(r)
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "vault-agent-operator",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&VaultAgentReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "VaultAgent")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}