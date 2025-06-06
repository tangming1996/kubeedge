/*
Copyright 2019 The KubeEdge Authors.

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

package device_test

import (
	"encoding/json"
	"net/http"
	"strings"

	MQTT "github.com/eclipse/paho.mqtt.golang"
	_ "github.com/mattn/go-sqlite3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kubeedge/kubeedge/edge/pkg/devicetwin/dtcommon"
	"github.com/kubeedge/kubeedge/edge/pkg/devicetwin/dttype"
	"github.com/kubeedge/kubeedge/edge/test/integration/utils/common"
	"github.com/kubeedge/kubeedge/edge/test/integration/utils/helpers"
)

// Devicestate from subscribed MQTT topic
var DeviceState string

type DeviceUpdates struct {
	EventID     string `json:"event_id"`
	Timestamp   int64  `json:"timestamp"`
	DeviceField `json:"device"`
}

type DeviceField struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	LastOnline string `json:"last_online"`
}

type MembershipUpdate struct {
	BaseMessage
	AddDevices    []helpers.Device `json:"added_devices"`
	RemoveDevices []helpers.Device `json:"removed_devices"`
}

type BaseMessage struct {
	EventID   string `json:"event_id"`
	Timestamp int64  `json:"timestamp"`
}

//var MemDeviceUpdate MembershipUpdate

var MemDeviceUpdate *MembershipUpdate

var TokenClient Token
var ClientOpts *MQTT.ClientOptions
var Client MQTT.Client

func SubMessageReceived(_ MQTT.Client, message MQTT.Message) {
	var deviceState DeviceUpdates
	topic := dtcommon.DeviceETPrefix + DeviceIDN + dtcommon.DeviceETStateUpdateResultSuffix
	if message.Topic() == topic {
		devicePayload := message.Payload()
		err := json.Unmarshal(devicePayload, &deviceState)
		if err != nil {
			common.Fatalf("Unmarshall failed %s", err)
		}
	}
	DeviceState = deviceState.State
}
func DeviceSubscribed(_ MQTT.Client, message MQTT.Message) {
	topic := dtcommon.MemETPrefix + ctx.Cfg.NodeID + dtcommon.MemETUpdateSuffix
	if message.Topic() == topic {
		devicePayload := message.Payload()
		err := json.Unmarshal(devicePayload, MemDeviceUpdate)
		if err != nil {
			common.Fatalf("Unmarshall failed %s", err)
		}
	}
}

// Deviceid from the DB and assigning to it
var DeviceIDN string
var DeviceN dttype.Device
var DeviceIDWithAttr string
var DeviceATT dttype.Device
var DeviceIDWithTwin string
var DeviceTW dttype.Device

// Run Test cases
var _ = Describe("Event Bus Testing", func() {
	Context("Publish on eventbus topics throgh MQTT internal broker", func() {
		BeforeEach(func() {
			ClientOpts = helpers.HubClientInit(ctx.Cfg.MqttEndpoint, ClientID, "", "")
			Client = MQTT.NewClient(ClientOpts)
			if TokenClient = Client.Connect(); TokenClient.Wait() && TokenClient.Error() != nil {
				common.Fatalf("client.Connect() Error is %s", TokenClient.Error())
			}
		})
		AfterEach(func() {
			Client.Disconnect(1)
			common.PrintTestcaseNameandStatus()
		})
		It("TC_TEST_EBUS_1: Sending data to Cloud", func() {
			var data = "messagetoUpload_record_to_cloud"
			body, err := json.Marshal(data)
			if err != nil {
				common.Fatalf("Marshal failed %v", err)
			}
			if TokenClient = Client.Publish(UploadRecordToCloud, 0, false, body); TokenClient.Wait() && TokenClient.Error() != nil {
				common.Fatalf("client.Publish() Error is %s", TokenClient.Error())
			} else {
				common.Infof("client.Publish Success !!")
			}
			Expect(TokenClient.Error()).NotTo(HaveOccurred())

		})

		It("TC_TEST_EBUS_2: Sending data to device module", func() {
			var data = "messagetoDevice_status_update"
			body, err := json.Marshal(data)
			if err != nil {
				common.Fatalf("Marshal failed %v", err)
			}
			if TokenClient = Client.Publish(DevicestatusUpdate, 0, false, body); TokenClient.Wait() && TokenClient.Error() != nil {
				common.Fatalf("client.Publish() Error is %s", TokenClient.Error())
			} else {
				common.Infof("client.Publish Success !!")
			}
			Expect(TokenClient.Error()).NotTo(HaveOccurred())
			//Client.Disconnect(1)
		})

		It("TC_TEST_EBUS_3: Sending data to device twin module", func() {
			var data = "messagetoDevice_Twin_update"
			body, err := json.Marshal(data)
			if err != nil {
				common.Fatalf("Marshal failed %v", err)
			}
			if TokenClient = Client.Publish(DeviceTwinUpdate, 0, false, body); TokenClient.Wait() && TokenClient.Error() != nil {
				common.Fatalf("client.Publish() Error is %s", TokenClient.Error())
			} else {
				common.Infof("client.Publish Success !!")
			}
			Expect(TokenClient.Error()).NotTo(HaveOccurred())
		})

		It("TC_TEST_EBUS_4: Sending data to membership module", func() {
			var data = "messagetoDevice_Membership_update"
			body, err := json.Marshal(data)
			if err != nil {
				common.Fatalf("Marshal failed %v", err)
			}
			if TokenClient = Client.Publish(DeviceMembershipUpdate, 0, false, body); TokenClient.Wait() && TokenClient.Error() != nil {
				common.Fatalf("client.Publish() Error is %s", TokenClient.Error())
			} else {
				common.Infof("client.Publish Success !!")
			}
			Expect(TokenClient.Error()).NotTo(HaveOccurred())
		})

		It("TC_TEST_EBUS_5: Sending data to device module", func() {
			var data = "messagetoDevice_upload"
			body, err := json.Marshal(data)
			if err != nil {
				common.Fatalf("Marshal failed %v", err)
			}
			if TokenClient = Client.Publish(DeviceUpload, 0, false, body); TokenClient.Wait() && TokenClient.Error() != nil {
				common.Fatalf("client.Publish() Error is %s", TokenClient.Error())
			} else {
				common.Infof("client.Publish Success !!")
			}
			Expect(TokenClient.Error()).NotTo(HaveOccurred())
		})
	})

	Context("Publish on eventbus topics throgh MQTT internal broker", func() {
		BeforeEach(func() {
			common.Infof("Adding Mock device to edgenode !!")

			DeviceIDN = helpers.GenerateDeviceID("kubeedge-device-")
			DeviceN = helpers.CreateDevice(DeviceIDN, "edgedevice", "unknown")

			ClientOpts = helpers.HubClientInit(ctx.Cfg.MqttEndpoint, ClientID, "", "")
			Client = MQTT.NewClient(ClientOpts)
			if TokenClient = Client.Connect(); TokenClient.Wait() && TokenClient.Error() != nil {
				common.Fatalf("client.Connect() Error is %s", TokenClient.Error())
			}
			Expect(TokenClient.Error()).NotTo(HaveOccurred())
			devicetopic := dtcommon.MemETPrefix + ctx.Cfg.NodeID + dtcommon.MemETUpdateSuffix
			topic := dtcommon.DeviceETPrefix + DeviceIDN + dtcommon.DeviceETStateUpdateResultSuffix
			Token := Client.Subscribe(devicetopic, 0, DeviceSubscribed)
			if Token.Wait() && TokenClient.Error() != nil {
				common.Fatalf("Subscribe to Topic  Failed  %s, %s", TokenClient.Error(), topic)
			}

			Token = Client.Subscribe(topic, 0, SubMessageReceived)
			if Token.Wait() && TokenClient.Error() != nil {
				common.Fatalf("Subscribe to Topic  Failed  %s, %s", TokenClient.Error(), devicetopic)
			}
			IsDeviceAdded := helpers.HandleAddAndDeleteDevice(http.MethodPut, ctx.Cfg.TestManager+Devicehandler, DeviceN)
			Expect(IsDeviceAdded).Should(BeTrue())
		})
		AfterEach(func() {
			Client.Disconnect(1)
			common.PrintTestcaseNameandStatus()
		})

		It("TC_TEST_EBUS_6: change the device status to online from eventbus", func() {
			var message helpers.DeviceUpdate
			message.State = "online"
			topic := dtcommon.DeviceETPrefix + DeviceIDN + dtcommon.DeviceETStateUpdateResultSuffix
			body, err := json.Marshal(message)
			if err != nil {
				common.Fatalf("Marshal failed %v", err)
			}
			Eventually(func() string {
				var ID string
				for _, deviceEvent := range MemDeviceUpdate.AddDevices {
					if deviceEvent.ID == DeviceIDN {
						ID = deviceEvent.ID
						if TokenClient = Client.Publish(dtcommon.DeviceETPrefix+DeviceIDN+dtcommon.DeviceETStateUpdateSuffix, 0, false, body); TokenClient.Wait() && TokenClient.Error() != nil {
							common.Fatalf("client.Publish() Error is %s", TokenClient.Error())
						} else {
							common.Infof("client.Publish Success !!")
						}
					}
				}
				return ID
			}, "10s", "2s").Should(Equal(DeviceIDN), "Device state is not online within specified time")
			Expect(TokenClient.Error()).NotTo(HaveOccurred())
			Eventually(func() string {
				common.Infof("subscribed to the topic %v", topic)
				return DeviceState
			}, "10s", "2s").Should(Equal("online"), "Device state is not online within specified time")
		})

		It("TC_TEST_EBUS_7: change the device status to unknown from eventbus", func() {
			var message helpers.DeviceUpdate
			message.State = "unknown"
			topic := dtcommon.DeviceETPrefix + DeviceIDN + dtcommon.DeviceETStateUpdateResultSuffix
			body, err := json.Marshal(message)
			if err != nil {
				common.Fatalf("Marshal failed %v", err)
			}
			Eventually(func() string {
				var deviceEvent helpers.Device
				for _, deviceEvent = range MemDeviceUpdate.AddDevices {
					if strings.Compare(deviceEvent.ID, DeviceIDN) == 0 {
						if TokenClient = Client.Publish(dtcommon.DeviceETPrefix+DeviceIDN+dtcommon.DeviceETStateUpdateSuffix, 0, false, body); TokenClient.Wait() && TokenClient.Error() != nil {
							common.Fatalf("client.Publish() Error is %s", TokenClient.Error())
						} else {
							common.Infof("client.Publish Success !!")
						}
					}
				}
				return deviceEvent.ID
			}, "10s", "2s").Should(Equal(DeviceIDN), "Device state is not online within specified time")
			Expect(TokenClient.Error()).NotTo(HaveOccurred())
			Eventually(func() string {
				common.Infof("subscribed to the topic %v", topic)
				return DeviceState
			}, "10s", "2s").Should(Equal("unknown"), "Device state is not unknown within specified time")
		})

		It("TC_TEST_EBUS_8: change the device status to offline from eventbus", func() {
			var message helpers.DeviceUpdate
			message.State = "offline"
			topic := dtcommon.DeviceETPrefix + DeviceIDN + dtcommon.DeviceETStateUpdateResultSuffix
			body, err := json.Marshal(message)
			if err != nil {
				common.Fatalf("Marshal failed %v", err)
			}
			Eventually(func() string {
				var deviceEvent helpers.Device
				for _, deviceEvent = range MemDeviceUpdate.AddDevices {
					if strings.Compare(deviceEvent.ID, DeviceIDN) == 0 {
						if TokenClient = Client.Publish(dtcommon.DeviceETPrefix+DeviceIDN+dtcommon.DeviceETStateUpdateSuffix, 0, false, body); TokenClient.Wait() && TokenClient.Error() != nil {
							common.Fatalf("client.Publish() Error is %s", TokenClient.Error())
						} else {
							common.Infof("client.Publish Success !!")
						}
					}
				}
				return deviceEvent.ID
			}, "10s", "2s").Should(Equal(DeviceIDN), "Device state is not online within specified time")
			Expect(TokenClient.Error()).NotTo(HaveOccurred())
			Eventually(func() string {
				common.Infof("subscribed to the topic %v", topic)
				return DeviceState
			}, "10s", "2s").Should(Equal("offline"), "Device state is not offline within specified time")
		})

	})
	Context(" Add a device with Twin attributes", func() {
		BeforeEach(func() {

		})
		AfterEach(func() {
			common.PrintTestcaseNameandStatus()
		})
		It("TC_TEST_EBUS_9: Add a sample device with device attributes to kubeedge node", func() {
			//Generating Device ID
			DeviceIDWithAttr = helpers.GenerateDeviceID("kubeedge-device-WithDeviceAttributes")
			//Generate a Device
			DeviceATT = helpers.CreateDevice(DeviceIDWithAttr, "DeviceATT", "unknown")
			//Add Attribute to device
			helpers.AddDeviceAttribute(DeviceATT, "Temperature", "25.25", "float")

			IsDeviceAdded := helpers.HandleAddAndDeleteDevice(http.MethodPut, ctx.Cfg.TestManager+Devicehandler, DeviceATT)
			Expect(IsDeviceAdded).Should(BeTrue())

			Eventually(func() string {
				attributeDB := helpers.GetDeviceAttributesFromDB(DeviceIDWithAttr, "Temperature")
				common.Infof("DeviceID= %s, Value= %s", attributeDB.DeviceID, attributeDB.Value)
				return attributeDB.Value
			}, "60s", "2s").Should(Equal("25.25"), "Device is not added within specified time")

		})

		It("TC_TEST_EBUS_10: Add a sample device with Twin attributes to kubeedge node", func() {
			//Generating Device ID
			DeviceIDWithTwin = helpers.GenerateDeviceID("kubeedge-device-WithTwinAttributes")
			//Generate a Device
			DeviceTW = helpers.CreateDevice(DeviceIDWithTwin, "DeviceTW", "unknown")
			//Add twin attribute
			helpers.AddTwinAttribute(DeviceTW, "Temperature", "25.25", "float")

			IsDeviceAdded := helpers.HandleAddAndDeleteDevice(http.MethodPut, ctx.Cfg.TestManager+Devicehandler, DeviceTW)
			Expect(IsDeviceAdded).Should(BeTrue())

			Eventually(func() string {
				attributeDB := helpers.GetTwinAttributesFromDB(DeviceIDWithTwin, "Temperature")
				common.Infof("DeviceID= %s, Value= %s", attributeDB.DeviceID, attributeDB.Expected)
				return attributeDB.Expected
			}, "60s", "2s").Should(Equal("25.25"), "Device is not added within specified time")

		})

		It("TC_TEST_EBUS_11: Update existing device with new attributes", func() {

			//Generate a Device
			device := helpers.CreateDevice(DeviceIDWithAttr, "DeviceATT", "unknown")
			//Add Attribute to device
			helpers.AddDeviceAttribute(device, "Temperature", "50.50", "float")

			IsDeviceAdded := helpers.HandleAddAndDeleteDevice(http.MethodPut, ctx.Cfg.TestManager+Devicehandler, device)
			Expect(IsDeviceAdded).Should(BeTrue())

			Eventually(func() string {
				attributeDB := helpers.GetDeviceAttributesFromDB(DeviceIDWithAttr, "Temperature")
				common.Infof("DeviceID= %s, Value= %s", attributeDB.DeviceID, attributeDB.Value)
				return attributeDB.Value
			}, "60s", "2s").Should(Equal("50.50"), "Device Attributes are not updated within specified time")

		})

		It("TC_TEST_EBUS_12: Update existing device with new Twin attributes", func() {

			//Generate a Device
			device := helpers.CreateDevice(DeviceIDWithTwin, "DeviceTW", "unknown")
			//Add twin attribute
			helpers.AddTwinAttribute(device, "Temperature", "50.50", "float")

			IsDeviceAdded := helpers.HandleAddAndDeleteDevice(http.MethodPut, ctx.Cfg.TestManager+Devicehandler, device)
			Expect(IsDeviceAdded).Should(BeTrue())

			Eventually(func() string {
				attributeDB := helpers.GetTwinAttributesFromDB(DeviceIDWithTwin, "Temperature")
				common.Infof("DeviceID= %s, Value= %s", attributeDB.DeviceID, attributeDB.Expected)
				return attributeDB.Expected
			}, "60s", "2s").Should(Equal("50.50"), "Device Twin Attributes are not updated within specified time")

		})

		It("TC_TEST_EBUS_13: Add a new Device attribute to existing device", func() {
			//Adding a new attribute to a device
			helpers.AddDeviceAttribute(DeviceATT, "Humidity", "30", "Int")

			IsDeviceAdded := helpers.HandleAddAndDeleteDevice(http.MethodPut, ctx.Cfg.TestManager+Devicehandler, DeviceATT)
			Expect(IsDeviceAdded).Should(BeTrue())

			Eventually(func() string {
				attributeDB := helpers.GetDeviceAttributesFromDB(DeviceIDWithAttr, "Humidity")
				common.Infof("DeviceID= %s, Value= %s", attributeDB.DeviceID, attributeDB.Value)
				return attributeDB.Value
			}, "60s", "2s").Should(Equal("30"), "Device Attributes are not Added within specified time")

		})

		It("TC_TEST_EBUS_14: Add a new Twin attribute to existing device", func() {
			//Preparing temporary Twin Attributes
			helpers.AddTwinAttribute(DeviceTW, "Humidity", "100.100", "float")

			IsDeviceAdded := helpers.HandleAddAndDeleteDevice(http.MethodPut, ctx.Cfg.TestManager+Devicehandler, DeviceTW)
			Expect(IsDeviceAdded).Should(BeTrue())

			Eventually(func() string {
				attributeDB := helpers.GetTwinAttributesFromDB(DeviceIDWithTwin, "Humidity")
				common.Infof("DeviceID= %s, Value= %s", attributeDB.DeviceID, attributeDB.Expected)
				return attributeDB.Expected
			}, "60s", "2s").Should(Equal("100.100"), "Device Twin Attributes are not Added within specified time")

		})
	})
})
