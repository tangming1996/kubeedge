package edge

import (
	"github.com/kubeedge/kubeedge/keadm/cmd/keadm/app/cmd/common"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
	"os"
)

func NewBatchJoinGenConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-config",
		Short: "Generate a YAML config file for batch join",
		Long:  `This command generates a template YAML configuration file for batch join.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			configTemplate := getConfigTemplate()

			// Marshal to YAML
			data, err := yaml.Marshal(&configTemplate)
			if err != nil {
				klog.Errorf("Error marshaling config template to YAML: %v", err)
				return err
			}

			// Write to file
			fileName := "config.yaml"
			if err := os.WriteFile(fileName, data, 0644); err != nil {
				klog.Errorf("Error writing config file: %v", err)
				return err
			}

			klog.Infof("Config template generated: %s", fileName)
			return nil
		},
	}
	return cmd
}

func getConfigTemplate() common.Config {
	offlinePackageDir := "/path/to/offline-package"
	uploadScriptDir := "/path/to/upload-script"
	PasswordAuth := &common.PasswordAuth{"dangerous"}
	return common.Config{
		Keadm: common.Keadm{
			Download: common.Download{
				Enable: false,
			},
			KeadmVersion:      "v1.19.0",
			ArchGroup:         []string{"amd64", "arm64"},
			OfflinePackageDir: &offlinePackageDir,
		},
		Nodes: []common.Node{
			{
				SSH: common.SSH{
					IP:       "192.168.1.1",
					Username: "root",
					SSHPort:  22,
					Auth: common.AuthConfig{
						Type:         "password",
						PasswordAuth: PasswordAuth,
					},
				},
				NodeName:      "node-1",
				Arch:          "amd64",
				KeadmCmd:      "join --cloudcore-ipport=127.0.0.1:10000",
				UploadFileDir: &uploadScriptDir,
			},
		},
		MaxRunNum: 1,
	}
}
