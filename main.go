package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/component-base/logs"
)

func test() {
	// Load kubeconfig
	kubeconfig := filepath.Join(
		"/home/ubuntu/.kube", // change this to your kubeconfig path
		"config",
	)
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Error building kubeconfig: %v", err)
	}

	// Create a clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating clientset: %v", err)
	}

	// List all services with type NodePort
	services, err := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Fatalf("Error listing services: %v", err)
	}

	for _, service := range services.Items {
		if service.Spec.Type == corev1.ServiceTypeNodePort {
			namespace := service.Namespace
			serviceName := service.Name
			nodePort := service.Spec.Ports[0].NodePort

			fmt.Printf("Service: %s\n", serviceName)
			fmt.Printf("Namespace: %s\n", namespace)
			fmt.Printf("NodePort: %d\n", nodePort)

			// Get the selector for the service
			selector := service.Spec.Selector
			labelSelector := metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: selector})

			// List the pods matching the selector
			pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			if err != nil {
				log.Fatalf("Error listing pods: %v", err)
			}

			fmt.Println("Pods and Node IPs:")
			for _, pod := range pods.Items {
				// Get the Calico IP address from pod annotations
				nodeName := pod.Spec.NodeName
				node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
				if err != nil {
					log.Fatalf("Error finding node: %v", err)
				}
				calicoIP := node.Annotations["projectcalico.org/IPv4Address"]

				if calicoIP == "" {
					calicoIP = "No Calico IP found"
				}

				fmt.Printf("Calico IP: %s\n", calicoIP)
			}
			fmt.Println("------")
		}
	}
}

func new_get_ips(clientset *kubernetes.Clientset) map[string][]string {
	deploymentIPMap := make(map[string][]string)

	// Get the list of pods in the cluster
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Println("Error listing pods:", err.Error())
		return nil
	}

	// Iterate through all pods
	for _, pod := range pods.Items {
		// Extract deployment name from pod labels (if exists)
		deploymentName := pod.Labels["app"] // assuming 'app' label contains deployment name
		if deploymentName == "" {
			continue // skip pods without a deployment label
		}

		// Get the node where the pod is running
		nodeName := pod.Spec.NodeName

		// Fetch the node information to get the Calico IP
		node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
		if err != nil {
			fmt.Println("Error finding node:", err.Error())
			continue
		}

		// Extract the Calico IP from the node annotations
		if calicoIP, exists := node.Annotations["projectcalico.org/IPv4Address"]; exists {
			ip := strings.Split(calicoIP, "/")[0] // Remove the CIDR suffix

			// Exclude master node (if necessary)
			if ip != "10.0.0.2" {
				// Append the IP to the corresponding deployment
				deploymentIPMap[deploymentName] = append(deploymentIPMap[deploymentName], ip)
			}
		}
	}
	// Print the deployment-to-IP mapping for debugging
	for deployment, ips := range deploymentIPMap {
		fmt.Printf("IPs for deployment %s : %s\n", deployment, strings.Join(ips, " "))
	}

	return deploymentIPMap
}

func convert_port_to_bytes(port int64) []byte {
	// Create a buffer to hold the binary representation
	buf := new(bytes.Buffer)

	// Write the port number in BigEndian format (network byte order)
	err := binary.Write(buf, binary.BigEndian, port)
	if err != nil {
		fmt.Println("Error converting port to bytes:", err)
		return nil
	}

	// Return the last two bytes, as port numbers are 16 bits (2 bytes)
	return buf.Bytes()[len(buf.Bytes())-2:]
}

func get_nodeport_using_client(clientset *kubernetes.Clientset, deploymentName string) []byte {
	services, err := clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Println("Error fetching services:", err.Error())
		return nil
	}

	// Loop through services to find the NodePort for the given deployment
	for _, service := range services.Items {
		if service.Spec.Selector["app"] == deploymentName && service.Spec.Type == corev1.ServiceTypeNodePort {
			nodePort := service.Spec.Ports[0].NodePort
			fmt.Printf("NodePort for deployment %s: %d\n", deploymentName, nodePort)

			// Convert the NodePort to bytes (replace with a suitable function if needed)
			return convert_port_to_bytes(int64(nodePort))
		}
	}

	fmt.Printf("No NodePort found for deployment %s\n", deploymentName)
	return nil
}

func get_num_replicas(ips []string) []byte {
	// Convert length of ips array to bytes
	buf := new(bytes.Buffer)
	num_replicas := int64(len(ips)) // Minus 1 for an extra newline
	if num_replicas < 0 {
		num_replicas = 0
	}
	//fmt.Println("Number of Replicas:", num_replicas)
	err_write := binary.Write(buf, binary.BigEndian, num_replicas)
	if err_write != nil {
		fmt.Println("Error writing to buffer:", err_write.Error())
		return nil
	}
	num_replicas_bytes := buf.Bytes()[len(buf.Bytes())-2 : len(buf.Bytes())] // Get the last 2 bytes
	return num_replicas_bytes
}

var virtualIPMap = make(map[string]string) // Maps deployment name to virtual IP
var baseIP = net.ParseIP("10.0.0.2").To4() // Ensure baseIP is IPv4

// Function to generate virtual IP for a deployment
func get_virtual_ip(deploymentName string) string {
	if ip, exists := virtualIPMap[deploymentName]; exists {
		return ip // If IP already assigned, return it
	}
	// If no IP assigned, assign the next IP
	nextIP := make(net.IP, len(baseIP))
	copy(nextIP, baseIP)
	virtualIPMap[deploymentName] = nextIP.String()

	// Increment baseIP for the next deployment
	incrementIP(baseIP)

	return nextIP.String()
}

// Function to increment an IP address (handles overflow properly)
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func send_control_packet() {
	fmt.Println("Sending control packet...")

	// Get the deployment-to-IPs mapping
	deploymentIPsMap := new_get_ips(clientset)
	if deploymentIPsMap == nil {
		fmt.Println("Error getting IPs. No active pods may be running.")
		return
	}

	// Loop through each deployment and send control packets separately
	for deployment, ips := range deploymentIPsMap {
		if len(ips) == 0 {
			fmt.Printf("No IPs for deployment %s\n", deployment)
			continue
		}

		// Prepare the payload for the current deployment
		fmt.Printf("Length for deployment %s is %d, Virtual IP: %s\n", deployment, len(ips), get_virtual_ip(deployment))

		payload := []byte{}

		// Get the virtual IP and convert it to bytes, add it to the payload first
		virtual_ip := net.ParseIP(get_virtual_ip(deployment)).To4()
		payload = append(payload, virtual_ip...)

		// Append port and replicas to payload
		port_bytes := get_nodeport_using_client(clientset, deployment) // Pass deployment name
		if port_bytes == nil {
			fmt.Printf("Error fetching NodePort for deployment %s\n", deployment)
			continue
		}
		num_replicas_bytes := get_num_replicas(ips) // Add replica count after virtual IP

		// Add port number and replica count to the payload
		payload = append(payload, port_bytes...)
		payload = append(payload, num_replicas_bytes...)

		// Add the IPs to the payload
		for _, ip := range ips {
			bytes_ip := net.ParseIP(ip)[12:16] // Only use the last 4 bytes (IPv4)
			payload = append(payload, bytes_ip...)
			fmt.Printf("Test for deployment %s : %s\n", deployment, ip)
		}

		// Establish connection and send packet
		connection, err := net.Dial("udp", "10.0.0.1:7777")
		if err != nil {
			fmt.Println("Error connecting:", err.Error())
			continue
		}

		_, err = connection.Write(payload)
		if err != nil {
			fmt.Println("Error sending:", err.Error())
			continue
		}

		fmt.Printf("Sent for deployment %s : %v\n", deployment, payload)
		connection.Close()
	}
}

var kubeconfig string
var clientset *kubernetes.Clientset

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(os.Getenv("HOME"), ".kube", "config"), "absolute path to the kubeconfig file")
}

func main() {
	test()
	flag.Parse()
	logs.InitLogs()
	defer logs.FlushLogs()

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		fmt.Println("Error building config", err.Error())
		return
	}
	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Println("Error creating clientset:", err.Error())
		return
	}
	// Send control packet called after creation of config
	send_control_packet()

	informerFactory := informers.NewSharedInformerFactory(clientset, time.Second*30)
	podInformer := informerFactory.Core().V1().Pods()
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			fmt.Println("Pod added: " + obj.(*v1.Pod).ObjectMeta.Name)
			send_control_packet()
		},
		DeleteFunc: func(obj interface{}) {
			fmt.Println("Pod deleted: " + obj.(*v1.Pod).ObjectMeta.Name)
			send_control_packet()
		},
		//UpdateFunc: ...,
	})

	nodeInformer := informerFactory.Core().V1().Nodes()
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			fmt.Println("Node added: " + obj.(*v1.Node).ObjectMeta.Name)
			// wait for the "cache" to sync
			// If we don't wait, the IPs may not be available yet
			// while the K8s files update with the new node
			// TODO: Find a better way to get the IPs or better timing for this
			time.Sleep(5 * time.Second)
			send_control_packet()
		},
		DeleteFunc: func(obj interface{}) {
			fmt.Println("Node deleted: " + obj.(*v1.Node).ObjectMeta.Name)
			send_control_packet()
		},
		//UpdateFunc: ...,
	})

	informerFactory.Start(wait.NeverStop)
	informerFactory.WaitForCacheSync(wait.NeverStop)
	select {} // block forever
}
