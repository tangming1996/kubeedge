/*
Copyright 2024 The KubeEdge Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package edge

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kubeedge/kubeedge/keadm/cmd/keadm/app/cmd/common"
	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	"k8s.io/klog/v2"
)

const (
	baseDir          = "/tmp/kubeedge/keadm"
	packageDir       = baseDir + "/package"
	binDir           = baseDir + "/bin"
	keadmDownloadURL = "https://github.com/kubeedge/kubeedge/releases/download"
)

// NewDeprecatedEdgeJoin returns KubeEdge batch edge join command.
func NewEdgeBatchJoin() *cobra.Command {
	bacthJoinOpts := &common.BatchJoinOptions{}
	cmd := &cobra.Command{
		Use:   "batch-process",
		Short: "Batch process nodes using a config file",
		Long:  `This command allows multiple nodes to join a cluster using a specified config file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if bacthJoinOpts.ConfigFile == "" {
				klog.Errorf("Please provide a config file using -c")
				os.Exit(1)
			}
			klog.Infof("Joining nodes using config file: %s\n", bacthJoinOpts.ConfigFile)
			return processBatchjoin(bacthJoinOpts.ConfigFile)
		},
	}
	// Adding the gen-config subcommand
	cmd.AddCommand(NewBatchJoinGenConfig())
	addBacthJoinOtherFlags(cmd, bacthJoinOpts)
	return cmd
}

func processBatchjoin(cfgFile string) error {
	configData, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		klog.Errorf("Error reading config file: %v", err)
		return err
	}
	var cfg common.Config
	err = yaml.Unmarshal(configData, &cfg)
	if err != nil {
		klog.Errorf("Error unmarshaling config data: %v", err)
		return err
	}

	// Get keadm packages
	if err := prepareKeadmPackages(&cfg); err != nil {
		klog.Errorf("Failed to download keadm packages: %v", err)
		return err
	}

	// Batch join edge nodes
	if err := batchJoinNodes(&cfg); err != nil {
		klog.Errorf("Failed to batch join nodes: %v", err)
		return err
	}
	return nil
}

// 根据配置获取 keadm 安装包，若 enable 为 true 则下载，否则从 offlinePackageDir 获取并解压
func prepareKeadmPackages(cfg *common.Config) error {
	if cfg.Keadm.Download.Enable {
		return downloadKeadmPackages(cfg)
	}
	return useOfflinePackages(cfg)
}

// 从用户提供的 offlinePackageDir 获取并解压安装包
func useOfflinePackages(cfg *common.Config) error {
	for _, arch := range cfg.Keadm.ArchGroup {
		packagePath := filepath.Join(*cfg.Keadm.OfflinePackageDir, fmt.Sprintf("keadm-%s-linux-%s.tar.gz", cfg.Keadm.KeadmVersion, arch))
		if _, err := os.Stat(packagePath); os.IsNotExist(err) {
			klog.Errorf("Package for %s not found in %s", arch, cfg.Keadm.OfflinePackageDir)
			return err
		}

		binOutputDir := filepath.Join(binDir, arch)
		if err := os.MkdirAll(binOutputDir, os.ModePerm); err != nil {
			klog.Errorf("Failed to create directory %s: %v", binOutputDir, err)
			return err
		}

		if err := extractTarGz(packagePath, binOutputDir); err != nil {
			return err
		}
		klog.Infof("Extracted keadm package for %s to %s", arch, binOutputDir)
	}
	return nil
}

// 下载 keadm 安装包
func downloadKeadmPackages(cfg *common.Config) error {
	for _, arch := range cfg.Keadm.ArchGroup {
		url := fmt.Sprintf("%s/%s/keadm-%s-linux-%s.tar.gz", keadmDownloadURL, cfg.Keadm.KeadmVersion, cfg.Keadm.KeadmVersion, arch)
		outputDir := filepath.Join(packageDir, arch)
		if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
			klog.Errorf("Failed to create directory %s: %v", outputDir, err)
			return err
		}
		outputPath := filepath.Join(outputDir, fmt.Sprintf("keadm-%s-linux-%s.tar.gz", cfg.Keadm.KeadmVersion, arch))

		// 解压到的目标目录
		binOutputDir := filepath.Join(binDir, arch)
		if err := os.MkdirAll(binOutputDir, os.ModePerm); err != nil {
			klog.Errorf("Failed to create directory %s: %v", binOutputDir, err)
			return err
		}

		// 先尝试解压文件
		klog.Infof("Attempting to extract keadm for %s to %s", arch, binOutputDir)
		if err := extractTarGz(outputPath, binOutputDir); err != nil {
			klog.Warningf("Failed to extract file %s, will attempt to download: %v", outputPath, err)

			// 下载文件
			klog.Infof("Downloading keadm for %s from %s to %s", arch, url, outputPath)
			if err := downloadFile(url, outputPath); err != nil {
				return err
			}

			// 下载完成后再解压
			klog.Infof("Re-attempting to extract keadm for %s to %s", arch, binOutputDir)
			if err := extractTarGz(outputPath, binOutputDir); err != nil {
				return fmt.Errorf("failed to extract file after download: %w", err)
			}
		}

		klog.Infof("Downloaded and extracted keadm for %s to %s", arch, binOutputDir)
	}
	return nil
}

// 从 URL 下载文件
func downloadFile(url, outputPath string) error {
	cmd := exec.Command("curl", "-L", "-o", outputPath, url)
	if err := cmd.Run(); err != nil {
		klog.Errorf("Failed to download file from %s: %v", url, err)
		return err
	}
	return nil
}

// 解压 tar.gz 文件
func extractTarGz(tarFile, destDir string) error {
	cmd := exec.Command("tar", "-xzvf", tarFile, "-C", destDir)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// 批量执行节点加入流程
func batchJoinNodes(cfg *common.Config) error {
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.MaxRunNum)
	for _, node := range cfg.Nodes {
		wg.Add(1)
		go func(node common.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := processNode(&node, cfg); err != nil {
				klog.Errorf("Failed to process node %s: %v", node.NodeName, err)
			} else {
				klog.Infof("Successfully processed node %s", node.NodeName)
			}
		}(node)
	}
	wg.Wait()
	return nil
}

// 处理单个节点的操作
func processNode(node *common.Node, cfg *common.Config) error {
	klog.Infof("Processing node %s", node.NodeName)
	client, err := connectSSH(node.SSH)
	if err != nil {
		klog.Errorf("Failed to connect to %s: %v", node.NodeName, err)
		return err
	}
	defer client.Close()

	if err := createRemoteDir(client, baseDir); err != nil {
		return err
	}

	if node.UploadFileDir != nil {
		if err := uploadFiles(client, node.NodeName, *node.UploadFileDir, baseDir); err != nil {
			return err
		}
	}

	keadmPath := filepath.Join(binDir, node.Arch, fmt.Sprintf("keadm-%s-linux-%s/keadm/keadm", cfg.Keadm.KeadmVersion, node.Arch))
	if err := uploadFile(client, node.NodeName, keadmPath, filepath.Join(baseDir, "keadm")); err != nil {
		return err
	}

	if err := executeKeadmCommand(client, node.NodeName, node.KeadmCmd); err != nil {
		return err
	}

	klog.Infof("Node %s processing completed", node.NodeName)
	return nil
}

// SSH 连接
func connectSSH(sshConfig common.SSH) (*ssh.Client, error) {
	var auth ssh.AuthMethod

	switch sshConfig.Auth.Type {
	case "password":
		if sshConfig.Auth.PasswordAuth != nil {
			auth = ssh.Password(sshConfig.Auth.PasswordAuth.Password)
		} else {
			return nil, fmt.Errorf("passwordAuth field is empty")
		}
	case "privateKey":
		if sshConfig.Auth.PrivateKeyAuth != nil {
			key, err := ioutil.ReadFile(sshConfig.Auth.PrivateKeyAuth.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key: %v", err)
			}
			signer, err := ssh.ParsePrivateKey(key)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
			auth = ssh.PublicKeys(signer)
		} else {
			return nil, fmt.Errorf("privateKeyAuth field is empty")
		}
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", sshConfig.Auth.Type)
	}
	config := &ssh.ClientConfig{
		User: sshConfig.Username,
		Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 5 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", sshConfig.IP, sshConfig.SSHPort)
	return ssh.Dial("tcp", addr, config)
}

// 创建远程目录
func createRemoteDir(client *ssh.Client, dir string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	cmd := fmt.Sprintf("mkdir -p %s", dir)
	if err := session.Run(cmd); err != nil {
		klog.Errorf("Failed to create directory %s: %v", dir, err)
		return err
	}
	return nil
}

// 传输文件
func uploadFile(client *ssh.Client, nodeName, srcPath, destPath string) error {
	// 使用 ssh.Client 创建一个 SFTP 客户端
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer sftpClient.Close()

	// 打开本地文件
	localFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer localFile.Close()

	// 创建远程文件
	remoteFile, err := sftpClient.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer remoteFile.Close()

	// 将本地文件内容复制到远程文件
	klog.Infof("Uploading file %s to %s:%s\n", srcPath, nodeName, destPath)
	_, err = remoteFile.ReadFrom(localFile)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	// 设置远程文件权限
	if err := sftpClient.Chmod(destPath, os.FileMode(0755)); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	klog.Infof("Successfully Uploaded file %s to %s:%s\n", srcPath, nodeName, destPath)
	return nil
}

// 批量传输脚本
func uploadFiles(client *ssh.Client, nodeName, srcDir, destDir string) error {
	files, err := ioutil.ReadDir(srcDir)
	if err != nil {
		klog.Errorf("Failed to read directory %s: %v", srcDir, err)
		return err
	}
	for _, file := range files {
		srcPath := filepath.Join(srcDir, file.Name())
		destPath := filepath.Join(destDir, file.Name())
		if err := uploadFile(client, nodeName, srcPath, destPath); err != nil {
			return err
		}
	}
	return nil
}

// 执行 keadm 命令
func executeKeadmCommand(client *ssh.Client, nodeName, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	var execCmd string
	parts := strings.Fields(cmd)
	if len(parts) >= 2 && parts[1] == "reset" {
		execCmd = fmt.Sprintf("cd %s && yes |./%s", baseDir, cmd)
	} else {
		execCmd = fmt.Sprintf("cd %s && ./%s", baseDir, cmd)
	}
	klog.Infof("%s: Executing command %s", nodeName, execCmd)
	if err := session.Run(execCmd); err != nil {
		klog.Errorf("Failed to execute keadm command %s: %v", execCmd, err)
		return err
	}
	return nil
}

func addBacthJoinOtherFlags(cmd *cobra.Command, batchJoinOpts *common.BatchJoinOptions) {
	cmd.Flags().StringVarP(&batchJoinOpts.ConfigFile, "config", "c", "", "Path to config file")
}
