package client

import (
	"crypto/x509"
	"fmt"
	"io"

	"github.com/gorilla/websocket"
	"k8s.io/klog/v2"

	"github.com/kubeedge/kubeedge/pkg/viaduct/pkg/api"
	"github.com/kubeedge/kubeedge/pkg/viaduct/pkg/comm"
	"github.com/kubeedge/kubeedge/pkg/viaduct/pkg/conn"
	"github.com/kubeedge/kubeedge/pkg/viaduct/pkg/lane"
)

// the client based on websocket
type WSClient struct {
	options Options
	exOpts  api.WSClientOption
	dialer  *websocket.Dialer
}

// new websocket client instance
func NewWSClient(options Options, exOpts interface{}) *WSClient {
	extendOption, ok := exOpts.(api.WSClientOption)
	if !ok {
		panic("bad websocket extend option")
	}

	return &WSClient{
		options: options,
		exOpts:  extendOption,
		dialer: &websocket.Dialer{
			TLSClientConfig:  options.TLSConfig,
			HandshakeTimeout: options.HandshakeTimeout,
		},
	}
}

// Connect try to connect remote server
func (c *WSClient) Connect() (conn.Connection, error) {
	header := c.exOpts.Header
	header.Add("ConnectionUse", string(c.options.ConnUse))
	wsConn, resp, err := c.dialer.Dial(c.options.Addr, header)
	if err == nil {
		klog.Infof("dial %s successfully", c.options.Addr)

		// do user's processing on connection or response
		if c.exOpts.Callback != nil {
			c.exOpts.Callback(wsConn, resp)
		}
		var peerCerts []*x509.Certificate
		if resp != nil && resp.TLS != nil {
			peerCerts = resp.TLS.PeerCertificates
		}
		return conn.NewConnection(&conn.ConnectionOptions{
			ConnType: api.ProtocolTypeWS,
			ConnUse:  c.options.ConnUse,
			Base:     wsConn,
			Consumer: c.options.Consumer,
			Handler:  c.options.Handler,
			CtrlLane: lane.NewLane(api.ProtocolTypeWS, wsConn),
			State: &conn.ConnectionState{
				State:            api.StatConnected,
				Headers:          c.exOpts.Header.Clone(),
				PeerCertificates: peerCerts,
			},
			AutoRoute: c.options.AutoRoute,
		}), nil
	}

	// something wrong!!
	var respMsg string
	if resp != nil {
		body, errRead := io.ReadAll(io.LimitReader(resp.Body, comm.MaxReadLength))
		if errRead == nil {
			respMsg = fmt.Sprintf("response code: %d, response body: %s", resp.StatusCode, string(body))
		} else {
			respMsg = fmt.Sprintf("response code: %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
	klog.Errorf("dial websocket error(%+v), response message: %s", err, respMsg)

	return nil, err
}
